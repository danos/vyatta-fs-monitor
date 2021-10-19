/*
 * Copyright (c) 2021, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <syslog.h>
#include <sys/statvfs.h>
#include <libmount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>
#include <confuse.h>

#include "fsmon.h"

/*
 * fsmon - daemon to periodically monitor filesystem used space and
 * mount permission changes. The daemon emits a log message
 *  - when the space usage exceeed user provided percentages
 *  - when the filesystem is mounted read-only.
 *
 *   fsmon [config-file]
 *
 *
 *  Signals:
 *    - SIGHUP - reload configuration
 *    - SIGTEM - terminate the daemon and exit
 *    - SIGUSR1 - print current state on stderr
 *
 * Configuration:
 *   The default localtion of the configuration file is /etc/vyatta/fsmon.conf. The
 *   configuration file may also be specified on the command line. The config file
 *   may contain multiple filesystem sections and each filsystem section may have one
 *   or more event sections.
 *
 *   Here is a sample config file
 *
 * default_prio = "warning"
 * default_facility = "local7"
 * interval = 2
 * filesystem {
 *    mountpoint = "/"
 *    event {
 * 	type = ro_remount
 * 	priority = "warning"
 * 	facility = "daemon"
 *    }
 *    event{
 *      type = high_usage
 *      percent = 10.00
 *      priority  = "warning"
 *      facility  = "daemon"
 *    }
 *
 *    event {
 *      type = high_usage
 *      percent = 20.00
 *      priority  = "warning"
 *      facility  = "daemon"
 *    }
 * }
 *
 * filesystem {
 *    mountpoint = "/home"
 *    event {
 * 	type = ro_remount
 * 	priority = "warning"
 * 	facility = "daemon"
 *    }
 * }
 */

static bool done;
static bool reload;
static bool dump_state;

static void signal_handler(int sig)
{
	switch (sig) {
	case SIGTERM:
		done = true;
		break;
	case SIGHUP:
		reload = true;
		break;
	case SIGUSR1:
		dump_state = true;
		break;
	default:
		fprintf(stderr, "Ignore received signal %d", sig);
		break;
	}
}

static int setup_signals(void)
{
	struct sigaction sa;

	sa.sa_handler = signal_handler;
	sa.sa_flags = SA_RESTART;
	sigemptyset(&sa.sa_mask);

	if (sigaction(SIGTERM, &sa, NULL) < 0) {
		fprintf(stderr,
			"cannot set handler for SIGTERM: %s", strerror(errno));
		return -1;
	}
	if (sigaction(SIGHUP, &sa, NULL) < 0) {
		fprintf(stderr,
			"cannot set handler for SIGUSR1: %s", strerror(errno));
		return -1;
	}
	if (sigaction(SIGUSR1, &sa, NULL) < 0) {
		fprintf(stderr,
			"cannot set handler for SIGUSR1: %s", strerror(errno));
		return -1;
	}
	return 0;
}

static struct fsm_fs_state *find_fs_state(struct fsm_context *ctx,
					  const char *path)
{
	int i;

	if (!ctx->nr_fs || !ctx->fsm_fs_state)
		return NULL;

	for(i = 0; i < ctx->nr_fs; ++i) {
		if (strcmp(ctx->fsm_fs_state[i].fs_cfg->path, path) == 0)
			return &ctx->fsm_fs_state[i];
	}
	return NULL;
}

static void copy_fs_state(struct fsm_fs_state *to, struct fsm_fs_state *from)
{
	to->usage = from->usage;
	to->prev_usage = from->prev_usage;
	to->ro_state = from->ro_state;
	to->prev_ro_state = from->ro_state;
}

static int reload_config(struct fsm_context *ctx)
{
	struct fsm_config *fsm_cfg;
	int nr_fs;
	struct fsm_fs_state *state;
	struct fsm_fs_state *old_state;
	int i;

	if (load_config(ctx->cfgfile, &fsm_cfg) < 0)
		return -1;

	nr_fs = fsm_cfg->nr_fs;
	state = calloc(nr_fs, sizeof(*state));
	if (state == NULL) {
		fprintf(stderr, "%s: Failed to allocate %zu bytes\n", __func__,
			nr_fs * sizeof(*state));
		fsm_config_free(fsm_cfg);
		return -1;
	}

	/* Copy old states if needed */
	for(i = 0; i < nr_fs; ++i) {
		/* copy old states if any */
		old_state = find_fs_state(ctx, fsm_cfg->fs[i].path);
		if (old_state)
			copy_fs_state(&state[i], old_state);
		state[i].fs_cfg = &fsm_cfg->fs[i];
	}

	if (ctx->fsm_fs_state)
		free(ctx->fsm_fs_state);
	if (ctx->fsm_cfg)
		fsm_config_free(ctx->fsm_cfg);

	ctx->fsm_cfg = fsm_cfg;
	ctx->nr_fs = nr_fs;
	ctx->fsm_fs_state = state;
	return 0;
}

static void free_mnt_table(struct libmnt_table **mnt_tbl)
{
	if (!mnt_tbl || !*mnt_tbl)
		return;

	mnt_unref_table(*mnt_tbl);
	*mnt_tbl = NULL;
}

/*
 * Update mount table if the file system mounts are changed.
 */
static int update_mnt_table(struct libmnt_table **mnt_tbl)
{
	struct libmnt_table *tb;
	struct libmnt_cache *cache;

	if (!mnt_tbl)
		return -1;

	free_mnt_table(mnt_tbl);

	tb = mnt_new_table_from_file(FSM_PATH_PROC_MOUNTINFO);
	if (tb == NULL)
		return -1;

	cache = mnt_new_cache();
	mnt_table_set_cache(tb, cache);
	mnt_unref_cache(cache);
	*mnt_tbl = tb;
	return 0;
}

static struct fsm_context *fsm_context_new()
{
	struct fsm_context *ctx;

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		fprintf(stderr, "%s: Failed to allocate %zu bytes\n", __func__,
			sizeof(*ctx));
		return NULL;
	}

	ctx->interval = FSM_INTERVAL;
	ctx->fd_mntinfo = open(FSM_PATH_PROC_MOUNTINFO, O_RDONLY, 0);
	if (ctx->fd_mntinfo < 0) {
		fprintf(stderr, "%s: Failed to open %s: %s", __func__,
			FSM_PATH_PROC_MOUNTINFO, strerror(errno));
		goto err;
	}

	if (update_mnt_table(&ctx->mnt_tbl) < 0) {
		fprintf(stderr, "%s: failed to init libmount mount table\n",
			__func__);
		goto err;
	}

	return ctx;
 err:
	free_mnt_table(&ctx->mnt_tbl);
	if (ctx->fd_mntinfo >= 0)
		close(ctx->fd_mntinfo);
	free(ctx);
	return NULL;
}

static void fsm_context_free(struct fsm_context *ctx)
{
	if (ctx->fsm_cfg)
		fsm_config_free(ctx->fsm_cfg);
	if (ctx->fsm_fs_state)
		free(ctx->fsm_fs_state);

	free_mnt_table(&ctx->mnt_tbl);
	free(ctx);
}

static float get_fs_usage_pct(struct statvfs *vfs)
{
	if (vfs->f_blocks == 0 || vfs->f_blocks == ~ ~((fsblkcnt_t) 0))
		return -1;

	float a = (vfs->f_bavail == ~((fsblkcnt_t) 0)) ? 0 : vfs->f_bavail;
	float u = (float)vfs->f_blocks - a;

	return (u * 100.0) / vfs->f_blocks;
}

static int get_fs_state(struct libmnt_table *tb, struct fsm_fs_state *fs_state)
{
	struct libmnt_fs *fs;
	struct statvfs vfs;
	float u;
	char *path;

	if (!tb || !fs_state || !fs_state->fs_cfg || !fs_state->fs_cfg->path) {
		fprintf(stderr, "%s: Invalid states\n", __func__);
		return -1;
	}

	path = fs_state->fs_cfg->path;

	fs = mnt_table_find_target(tb, path, MNT_ITER_BACKWARD);
	if (!fs || !mnt_fs_get_target(fs))
		return -1;

	/* Now get the fs stats */
	if (statvfs(path, &vfs) != 0)
		return -1;

	fs_state->prev_ro_state = fs_state->ro_state;
	fs_state->ro_state = (vfs.f_flag & ST_RDONLY) == ST_RDONLY;

	u = get_fs_usage_pct(&vfs);
	if (u < 0)
		return -1;

	if (u > 0) {
		fs_state->prev_usage = fs_state->usage;
		fs_state->usage = u;
	}
	return 0;
}

static void update_all_fs(struct fsm_context *ctx)
{
	int i;
	for(i = 0; i < ctx->nr_fs; ++i)
		get_fs_state(ctx->mnt_tbl, &ctx->fsm_fs_state[i]);

}

static int get_log_prio(struct fsm_context *ctx, struct fsm_event *ev)
{
	int prio = ctx->fsm_cfg->default_prio;
	int facility = ctx->fsm_cfg->default_facility;

	if (ev->log_priority > 0)
		prio = ev->log_priority;

	if (ev->log_facility > 0)
		facility = ev->log_facility;

	return facility | prio;
}

static void log_check_ro_remount(struct fsm_context *ctx,
				 struct fsm_fs_state *state,
				 struct fsm_event *ev)
{

	if (!state->ro_state || state->prev_ro_state)
		return;

	syslog(get_log_prio(ctx, ev),
	       "filesystem-monitor: Filesystem %s is mounted read-only\n",
	       state->fs_cfg->path);
}

static void log_check_used_space(struct fsm_context *ctx,
				 struct fsm_fs_state *state,
				 struct fsm_event *ev)
{
	if (state->usage < ev->high_usage
	    || state->prev_usage >= ev->high_usage)
		return;

	syslog(get_log_prio(ctx, ev),
	       "filesystem-monitor: Filesystem %s's space usage is %g%%, exceeds %g%%\n",
	       state->fs_cfg->path, state->usage, ev->high_usage);
}

static void log_fs_events(struct fsm_context *ctx, struct fsm_fs_state *state)
{
	struct fsm_fs *fs_cfg = state->fs_cfg;
	struct fsm_event *ev;

	for(ev = &fs_cfg->events[0]; ev < &fs_cfg->events[fs_cfg->nr_events];
	    ++ev) {
		if (ev->evtype == EVENT_FS_RO_REMOUNT)
			log_check_ro_remount(ctx, state, ev);
		else if (ev->evtype == EVENT_FS_USED_SPACE_THRESHOLD)
			log_check_used_space(ctx, state, ev);
	}
}

static void log_all_fs_events(struct fsm_context *ctx)
{
	struct fsm_fs_state *state;

	for(state = &ctx->fsm_fs_state[0];
	    state < &ctx->fsm_fs_state[ctx->nr_fs]; ++state) {
		log_fs_events(ctx, state);
	}
}

static void fsm_wait(struct fsm_context *ctx)
{
	struct pollfd pfd;
	int rv;

	pfd.fd = ctx->fd_mntinfo;
	pfd.events = POLLERR | POLLPRI;
	pfd.revents = 0;

	rv = poll(&pfd, 1, ctx->interval * 1000);

	if (rv >= 0) {
		if (pfd.revents & (POLLERR | POLLPRI))
			ctx->update_mnt_tbl = true;
	}
	return;
}

static void dump_ctx(struct fsm_context *ctx)
{
	int i, j;

	fprintf(stderr, "Filsystem Monitor Context:\n");
	fprintf(stderr, " interval=%d\n", ctx->interval);
	fprintf(stderr, " nr_fs=%d\n", ctx->nr_fs);
	for(i = 0; i < ctx->nr_fs; ++i) {
		struct fsm_fs_state *st = &ctx->fsm_fs_state[i];
		fprintf(stderr, "  path=%s\n", st->fs_cfg->path);
		fprintf(stderr, "    usage=%g prev_usage=%g\n", st->usage,
			st->prev_usage);
		fprintf(stderr, "    ro_state=%d prev_ro_state=%d\n",
			st->ro_state, st->prev_ro_state);
		fprintf(stderr, "    nr_events=%d\n", st->fs_cfg->nr_events);
		for(j = 0; j < st->fs_cfg->nr_events; ++j) {
			struct fsm_event *ev = &st->fs_cfg->events[j];
			fprintf(stderr, "      evtype=%d threshold=%g\n",
				ev->evtype, ev->high_usage);
		}
	}
	fprintf(stderr, "End Filesystem Monitor Context\n");
}

int main(int argc, char *argv[])
{
	struct fsm_context *ctx = NULL;
	int exit_code = 0;

	openlog(NULL, LOG_PID, LOG_DAEMON);

	if (setup_signals() < 0)
		exit(1);

	ctx = fsm_context_new();
	if (ctx == NULL)
		exit(1);

	if (argc == 2)
		ctx->cfgfile = argv[1];
	else
		ctx->cfgfile = FSM_CONFIG_FILE;

	if (reload_config(ctx) < 0) {
		fprintf(stderr, "Failed to load config file %s\n",
			ctx->cfgfile);
		exit(1);
	}

	ctx->interval = ctx->fsm_cfg->interval;

	while(!done) {
		if (dump_state) {
			dump_ctx(ctx);
			dump_state = false;
		}
		if (ctx->update_mnt_tbl) {
			if (update_mnt_table(&ctx->mnt_tbl) < 0) {
				exit_code = 1;
				goto end;
			}
			ctx->update_mnt_tbl = false;
		}
		if (reload) {
			if (reload_config(ctx) < 0) {
				exit_code = 1;
				goto end;
			}
		}
		update_all_fs(ctx);
		log_all_fs_events(ctx);
		if (!done)
			fsm_wait(ctx);
	}

 end:
	fprintf(stderr, "Exiting %s with exit code %d\n", argv[0], exit_code);
	fsm_context_free(ctx);
	exit(exit_code);
}
