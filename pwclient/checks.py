# Patchwork command line client
# Copyright (C) 2018 Stephen Finucane <stephen@that.guru>
# Copyright (C) 2008 Nate Case <ncase@xes-inc.com>
#
# SPDX-License-Identifier: GPL-2.0-or-later

import re
import sys

from . import exceptions


def action_list(api, patch_id=None, user=None):
    checks = api.check_list(patch_id, user)
    print("%-5s %-16s %-8s %s" % ("ID", "Context", "State", "Patch"))
    print("%-5s %-16s %-8s %s" % ("--", "-------", "-----", "-----"))
    for check in checks:
        print(
            "%-5s %-16s %-8s %s"
            % (check['id'], check['context'], check['state'], check['patch'])
        )


def action_info(api, patch_id, check_id):
    check = api.check_get(patch_id, check_id)
    s = f"Information for check id {int(check_id)}"
    print(s)
    print('-' * len(s))
    for key, value in sorted(check.items()):
        print("- %- 14s: %s" % (key, value))


def action_get(api, patch_id, format_str=None):
    checks = api.check_list(patch_id, user=None)
    if checks is None:
        return

    if format_str:
        format_field_re = re.compile('%{([a-z0-9_]+)}')

        def check_field(matchobj):
            fieldname = matchobj.group(1)

            return str(check[fieldname])

        for check in checks:
            print(format_field_re.sub(check_field, format_str))
    else:
        s = f"Check information for patch id {int(patch_id)}"
        print(s)
        print('-' * len(s))
        out = []
        for check in checks:
            cout = []
            for key, value in sorted(check.items()):
                value = f" {str(value)}" if value else value
                cout.append("- %- 14s:%s" % (key, value))
            out.append("\n".join(cout))
        print("\n\n".join(out))


def action_create(api, patch_id, context, state, url, description):
    try:
        api.check_create(patch_id, context, state, url, description)
    except exceptions.APIError as exc:
        sys.stderr.write(str(exc))
