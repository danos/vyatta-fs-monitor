/*
 * Copyright (c) 2021, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _FSMONITOR_H
#define _FSMONITOR_H

#define	MINUTE	(60)

#define FSM_INTERVAL	(2*MINUTE)
#define FSM_PATH_PROC_MOUNTINFO "/proc/self/mountinfo"
#define FSM_MIN_USED_SPACE_THRESHOLD 1.0
#define FSM_CONFIG_FILE "/etc/vyatta/fsmon.conf"

enum fsm_event_types {
	EVENT_NONE = 0,
	EVENT_FS_RO_REMOUNT,
	EVENT_FS_USED_SPACE_THRESHOLD,
	EVENT_MAX,
};

struct fsm_event {
	int evtype;
	int log_priority;
	int log_facility;
	float high_usage;
};

/*
 * Monitor for each file system.
 */
struct fsm_fs {
	char *path;
	int nr_events;
	struct fsm_event *events;
};

struct fsm_config {
	int default_prio;
	int default_facility;
	int interval;

	int nr_fs;
	struct fsm_fs *fs;
};

struct fsm_fs_state {
	struct fsm_fs *fs_cfg;
	float usage; /* Current file system usage */
	float prev_usage; /* usage at last check */
	bool ro_state; /* current read only state */
	bool prev_ro_state; /* last ro state */
};

struct fsm_context {
	const char *cfgfile;
	struct fsm_config *fsm_cfg;

	int nr_fs;
	struct fsm_fs_state *fsm_fs_state;

	int interval;
	bool update_mnt_tbl;
	struct libmnt_table *mnt_tbl;
	int fd_mntinfo;
};


int load_config(const char *cfgfile, struct fsm_config **ctx);
void fsm_config_free(struct fsm_config *cfg);

#endif /* _FS_MONITRO_H */
