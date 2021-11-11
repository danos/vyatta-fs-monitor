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
#include <sys/syslog.h>
#include <confuse.h>

#include "fsmon.h"

struct nvpair {
	char *name;
	int val;
};

static struct nvpair prio_names[] = {
	{"alert", LOG_ALERT},
	{"crit", LOG_CRIT},
	{"debug", LOG_DEBUG},
	{"emerg", LOG_EMERG},
	{"err", LOG_ERR},
	{"info", LOG_INFO},
	{"notice", LOG_NOTICE},
	{"warning", LOG_WARNING},
	{NULL, -1},
};

static struct nvpair facility_names[] = {
	{"auth", LOG_AUTH},
	{"authpriv", LOG_AUTHPRIV},
	{"cron", LOG_CRON},
	{"daemon", LOG_DAEMON},
	{"ftp", LOG_FTP},
	{"kern", LOG_KERN},
	{"lpr", LOG_LPR},
	{"mail", LOG_MAIL},
	{"news", LOG_NEWS},
	{"syslog", LOG_SYSLOG},
	{"user", LOG_USER},
	{"uucp", LOG_UUCP},
	{"local0", LOG_LOCAL0},
	{"local1", LOG_LOCAL1},
	{"local2", LOG_LOCAL2},
	{"local3", LOG_LOCAL3},
	{"local4", LOG_LOCAL4},
	{"local5", LOG_LOCAL5},
	{"local6", LOG_LOCAL6},
	{"local7", LOG_LOCAL7},
	{NULL, -1}
};

static struct nvpair fs_event_names[] = {
	{"ro_remount", EVENT_FS_RO_REMOUNT},
	{"high_usage", EVENT_FS_USED_SPACE_THRESHOLD},
	{NULL, -1},
};

static int nvpair_lookup(struct nvpair *table, const char *s, int *val)
{
	struct nvpair *p;

	if (s == NULL)
		return -1;

	for(p = &table[0]; p->name != NULL; ++p) {
		if (strcmp(s, p->name) == 0) {
			*val = p->val;
			return 0;
		}
	}
	return -1;
}

static int lookup_priority(const char *s, int *val)
{
	return nvpair_lookup(prio_names, s, val);
}

static int lookup_facility(const char *s, int *val)
{
	return nvpair_lookup(facility_names, s, val);
}

static int lookup_event(const char *s, int *val)
{
	return nvpair_lookup(fs_event_names, s, val);
}

static int load_config_ev(cfg_t *fs_cfg, struct fsm_event **pev, int *count)
{
	struct fsm_event *ev;
	cfg_t *ev_cfg;
	const char *evstr;
	const char *prio;
	const char *facility;
	int n;
	int i;

	if (!fs_cfg)
		return -1;

	n = cfg_size(fs_cfg, "event");
	if (n <= 0) {
		fprintf(stderr, "%s:no event to monitor\n", __func__);
		return -1;
	}

	ev = calloc(n, sizeof(*ev));
	if (ev == NULL) {
		fprintf(stderr, "%s:Failed to allocate memory %zu\n", __func__,
			n * sizeof(*ev));
		return -1;
	}

	for(i = 0; i < n; ++i) {
		ev_cfg = cfg_getnsec(fs_cfg, "event", i);
		if (!ev_cfg) {
			fprintf(stderr, "%s:no event monitor %d\n", __func__,
				i);
			goto err;
		}

		evstr = cfg_getstr(ev_cfg, "type");
		if (lookup_event(evstr, &ev[i].evtype) == -1) {
			fprintf(stderr, "%s:invalid event monitor %s\n",
				__func__, evstr ? evstr : "(null)");
			goto err;
		}

		prio = cfg_getstr(ev_cfg, "priority");
		if (prio != NULL
		    && lookup_priority(prio, &ev[i].log_priority) == -1) {
			fprintf(stderr, "%s:event %d: invalid syslog prio %s\n",
				__func__, i, prio);
			goto err;
		}

		facility = cfg_getstr(ev_cfg, "facility");
		if (facility != NULL
		    && lookup_facility(facility, &ev[i].log_facility) == -1) {
			fprintf(stderr,
				"%s:event %d: invalid syslog facility %s\n",
				__func__, i, facility);
			goto err;
		}

		if (ev[i].evtype == EVENT_FS_USED_SPACE_THRESHOLD) {
			ev[i].high_usage = cfg_getfloat(ev_cfg, "percent");
		        if (ev[i].high_usage <= FSM_MIN_USED_SPACE_THRESHOLD) {
				fprintf(stderr,
					"%s: event %d: invalid usage percent %g\n",
					__func__, i, ev[i].high_usage);
				goto err;
			}
		}
	}
	if (pev)
		*pev = ev;
	if (count)
		*count = n;
	return 0;
 err:
	free(ev);
	return -1;
}

static int load_config_fs(cfg_t *cfg, struct fsm_fs **pfs, int *count)
{
	int i;
	int n;
	const char *mnt;
	cfg_t *fs_cfg;

	n = cfg_size(cfg, "filesystem");
	if (n == 0) {
		*pfs = NULL;
		*count = 0;
		fprintf(stderr, "%s:no filesystem sections in config\n",
			__func__);
		return 0;
	}

	struct fsm_fs *fs = calloc(sizeof(*fs), n);
	if (fs == NULL) {
		fprintf(stderr, "%s:falied to allocate %zu bytes\n", __func__,
			n * sizeof(*fs));
		return -1;
	}

	for(i = 0; i < n; ++i) {
		fs_cfg = cfg_getnsec(cfg, "filesystem", i);
		if (!fs_cfg) {
			fprintf(stderr, "%s: failed to get filesytem %d\n",
				__func__, i);
			goto err;
		}

		mnt = cfg_getstr(fs_cfg, "mountpoint");
		if (mnt == NULL) {
			fprintf(stderr,
				"%s:No mountpoint in config filesystem %d\n",
				__func__, i);
			goto err;
		}
		fs[i].path = strdup(mnt);
		if (fs[i].path == NULL) {
			fprintf(stderr,
				"%s:filesystem %s: Failed to allocate memory of size %zu\n",
				__func__, mnt, strlen(mnt));
			goto err;
		}

		if (load_config_ev(fs_cfg, &fs[i].events, &fs[i].nr_events) ==
		    -1) {
			fprintf(stderr,
				"filesystem %s: failed to get event sections\n",
				mnt);
			goto err;
		}
	}
	if (pfs)
		*pfs = fs;
	if (count)
		*count = n;
	return 0;
 err:
	for(i = 0; i < n; ++i) {
		if (fs[i].path)
			free(fs[i].path);
		if (fs[i].events)
			free(fs[i].events);
	}
	free(fs);
	return -1;
}

int load_config(const char *cfgfile, struct fsm_config **pconf)
{
	int rc = 0;
	cfg_t *cfg;
	char *tmp;
	struct fsm_config *fsm_conf;

	cfg_opt_t event_opts[] = {
		CFG_STR("type", NULL, CFGF_NONE),
		CFG_FLOAT("percent", 0, CFGF_NONE),
		CFG_STR("priority", NULL, CFGF_NONE),
		CFG_STR("facility", NULL, CFGF_NONE),
		CFG_END(),
	};
	cfg_opt_t fs_opts[] = {
		CFG_STR("mountpoint", NULL, CFGF_NONE),
		CFG_SEC("event", event_opts, CFGF_MULTI),
		CFG_END(),
	};
	cfg_opt_t opts[] = {
		CFG_STR("default_priority", "warning", CFGF_NONE),
		CFG_STR("default_facility", "daemon", CFGF_NONE),
		CFG_INT("interval", FSM_INTERVAL, CFGF_NONE),
		CFG_SEC("filesystem", fs_opts, CFGF_MULTI),
		CFG_END(),
	};

	cfg = cfg_init(opts, CFGF_NONE);
	rc = cfg_parse(cfg, cfgfile);

	if (rc == CFG_FILE_ERROR) {
		perror(cfgfile);
		rc = -1;
		goto end;
	} else if (rc == CFG_PARSE_ERROR) {
		fprintf(stderr, "%s:Failed to parse %s\n", __func__, cfgfile);
		rc = -1;
		goto end;
	}

	fsm_conf = calloc(1, sizeof(*fsm_conf));
	if (fsm_conf == NULL) {
		fprintf(stderr, "%s:failed to allocate %zu bytes of memory\n",
			__func__, sizeof(*fsm_conf));
		rc = -1;
		goto end;
	}

	tmp = cfg_getstr(cfg, "default_priority");
	if (lookup_priority(tmp, &fsm_conf->default_prio) == -1) {
		fprintf(stderr, "%s:Bad default_prio %s\n", __func__,
			tmp ? tmp : "(null)");
		rc = -1;
		goto cfgerr;
	}

	tmp = cfg_getstr(cfg, "default_facility");
	if (lookup_facility(tmp, &fsm_conf->default_prio) == -1) {
		fprintf(stderr, "%s:Bad default_facility %s\n", __func__,
			tmp ? tmp : "(null)");
		rc = -1;
		goto cfgerr;
	}

	fsm_conf->interval = cfg_getint(cfg, "interval");

	if (load_config_fs(cfg, &fsm_conf->fs, &fsm_conf->nr_fs) == -1) {
		fprintf(stderr, "%s:falied to load monitored filesystems\n",
			__func__);
		rc = -1;
		goto cfgerr;
	}
	*pconf = fsm_conf;
	goto end;

 cfgerr:
	free(fsm_conf);
 end:
	cfg_free(cfg);
	return rc;
}

void fsm_config_free(struct fsm_config *cfg)
{
	int i;
	if (cfg->fs) {
		for(i = 0; i < cfg->nr_fs; ++i) {
			if (cfg->fs[i].events)
				free(cfg->fs[i].events);
		}
		free(cfg->fs);
	}
	free(cfg);
}
