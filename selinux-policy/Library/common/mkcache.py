#!/usr/bin/env python3
#
# This script generates a sqlite-based rule cache from a selinux policy
# currently active on the system, to be used by further queries.
#

import os, sys
import sqlite3
import setools

#
# LIMITATIONS !!!
# - currently no sql views that would provide functionality matching sesearch
#   - the current views return only what's searched, not everything around it
#   - eg. searching attr will return entry for that attr, not for all its types
#     - searching by types defined using attr works the same as for sesearch
# - only allow, type_trans, dontaudit
# - type_trans
#   - no attributes support
#

if len(sys.argv) < 2:
    print("usage: {0} <db_filename>".format(sys.argv[0]), file=sys.stderr)
    sys.exit(1)

dbfile = sys.argv[1]
if os.path.lexists(dbfile):
    print("error: {0} already exists".format(dbfile), file=sys.stderr)
    sys.exit(1)

conn = sqlite3.connect(dbfile)

cur = conn.cursor()
#cur.execute('PRAGMA foreign_keys = ON')

#
## creating tables
#

cur.executescript("""
    /*
     * global rule properties (applicable to any ruletype)
     */
    -- indexed by attribute name, maps to one or more "types",
    -- - also contains entries for non-attributes (regular types), those
    --   have `attr` == `type`
    -- - also contains entries for attributes themselves, also with
    --   `attr` == `type`
    CREATE TABLE 'attrs' (
        'attr' VARCHAR NOT NULL,
        'type' VARCHAR NOT NULL
    );
    CREATE TABLE 'perms' (
        'id' INTEGER UNSIGNED NOT NULL,
        'perm' VARCHAR NOT NULL
    );
    CREATE TABLE 'bools' (
        'id' INTEGER UNSIGNED NOT NULL,
        'bool' VARCHAR NOT NULL,
        'state' BOOLEAN NOT NULL  -- T/F of the whole conditional block
    );
    CREATE TABLE 'filenames' (
        'id' INTEGER UNSIGNED NOT NULL,
        'filename' VARCHAR NOT NULL
    );

    /*
     * per-ruletype tables
     */
    CREATE TABLE 'allow' (
        'id' INTEGER UNSIGNED NOT NULL PRIMARY KEY,
        'source' VARCHAR NOT NULL,
        'target' VARCHAR NOT NULL,
        'class' VARCHAR NOT NULL
    );
    CREATE TABLE 'type_trans' (
        'id' INTEGER UNSIGNED NOT NULL PRIMARY KEY,
        'source' VARCHAR NOT NULL,
        'target' VARCHAR NOT NULL,
        'class' VARCHAR NOT NULL,
        'default' VARCHAR NOT NULL
    );
    CREATE TABLE 'dontaudit' (
        'id' INTEGER UNSIGNED NOT NULL PRIMARY KEY,
        'source' VARCHAR NOT NULL,
        'target' VARCHAR NOT NULL,
        'class' VARCHAR NOT NULL
    );

    /*
     * views for lookup
     */
    CREATE VIEW 'allow_lookup' AS
    SELECT
        "asrc"."type" AS 'source',
        "atgt"."type" AS 'target',
        "a"."class" AS 'class',
        "p"."perm" AS 'perm',
        "b"."bool" AS 'bool',
        "b"."state" AS 'boolstate'
    FROM "allow" 'a'
        LEFT JOIN "attrs" 'asrc' ON "a"."source" = "asrc"."attr"
        LEFT JOIN "attrs" 'atgt' ON "a"."target" = "atgt"."attr"
        LEFT JOIN "perms" 'p' ON "a"."id" = "p"."id"
        LEFT JOIN "bools" 'b' ON "a"."id" = "b"."id";

    CREATE VIEW 'type_trans_lookup' AS
    SELECT
        "tt"."source" AS 'source',
        "tt"."target" AS 'target',
        "tt"."class" AS 'class',
        "tt"."default" AS 'default',
        "f"."filename" AS 'filename',
        "b"."bool" AS 'bool',
        "b"."state" AS 'boolstate'
    FROM "type_trans" 'tt'
        LEFT JOIN "filenames" 'f' ON "tt"."id" = "f"."id"
        LEFT JOIN "bools" 'b' ON "tt"."id" = "b"."id";

    CREATE VIEW 'dontaudit_lookup' AS
    SELECT
        "asrc"."type" AS 'source',
        "atgt"."type" AS 'target',
        "da"."class" AS 'class',
        "p"."perm" AS 'perm',
        "b"."bool" AS 'bool',
        "b"."state" AS 'boolstate'
    FROM "dontaudit" 'da'
        LEFT JOIN "attrs" 'asrc' ON "da"."source" = "asrc"."attr"
        LEFT JOIN "attrs" 'atgt' ON "da"."target" = "atgt"."attr"
        LEFT JOIN "perms" 'p' ON "da"."id" = "p"."id"
        LEFT JOIN "bools" 'b' ON "da"."id" = "b"."id";
""")

#
## filling up the tables
#

def extract_attrs(rule, known_attrs=set()):
    try:
        typeattribute = setools.policyrep.TypeAttribute
    except AttributeError:
        # older setools
        typeattribute = setools.policyrep.typeattr.TypeAttribute

    # treat types as expandable attrs
    for attr in (rule.source, rule.target):
        attr_str = str(attr)  # expensive
        if attr_str not in known_attrs:
            # attr->attr
            if isinstance(attr, typeattribute):
                cur.execute('INSERT INTO "attrs" VALUES (?,?)',
                            (attr_str, attr_str))
            # attr->types and type->type
            for child in attr.expand():
                cur.execute('INSERT INTO "attrs" VALUES (?,?)',
                            (attr_str, str(child)))
            known_attrs.add(attr_str)

known_attrs = set()
for ruleid, rule in enumerate(setools.SELinuxPolicy().terules()):
    # rule attributes
    extract_attrs(rule, known_attrs=known_attrs)
    # permissions
    if hasattr(rule, 'perms'):
        for perm in rule.perms:
            cur.execute('INSERT INTO "perms" VALUES (?,?)',
                        (ruleid, str(perm)))
    # booleans
    #if hasattr(rule, 'conditional'):
    #    truth = next(filter(lambda x: x.result == True,
    #                        rule.conditional.truth_table())).values
    #    for boolname, boolstate in truth.items():
    #        cur.execute("INSERT INTO 'bools' VALUES (?,?,?)",
    #                    (ruleid, boolname, boolstate))
    # booleans as expression strings, as seen in sesearch output
    if hasattr(rule, 'conditional'):
        cur.execute('INSERT INTO "bools" VALUES (?,?,?)',
                    (ruleid, str(rule.conditional), rule.conditional_block))

    # filename
    if hasattr(rule, 'filename'):
        cur.execute('INSERT INTO "filenames" VALUES (?,?)',
                    (ruleid, rule.filename))
    # per-ruletype
    if rule.ruletype == setools.TERuletype.allow:
        cur.execute('INSERT INTO "allow" VALUES (?,?,?,?)',
                    (ruleid, str(rule.source), str(rule.target),
                     str(rule.tclass)))
    elif rule.ruletype == setools.TERuletype.type_transition:
        cur.execute('INSERT INTO "type_trans" VALUES (?,?,?,?,?)',
                    (ruleid, str(rule.source), str(rule.target),
                     str(rule.tclass), str(rule.default)))
    elif rule.ruletype == setools.TERuletype.dontaudit:
        cur.execute('INSERT INTO "dontaudit" VALUES (?,?,?,?)',
                    (ruleid, str(rule.source), str(rule.target),
                     str(rule.tclass)))

#
## creating indices
#

# separate CREATE INDEX after filling up tables saves about 20% of
# DB creation time + makes queries cca 30% faster due to better index
# optimization
cur.executescript("""
    CREATE UNIQUE INDEX 'attrs_both' ON "attrs" ("attr", "type");
    CREATE INDEX 'perms_id' ON "perms" ("id");
    CREATE INDEX 'perms_perm' ON "perms" ("perm");
    CREATE INDEX 'bools_id' ON "bools" ("id");
    CREATE INDEX 'bools_bool' ON "bools" ("bool", "state");
    CREATE INDEX 'filenames_id' ON "filenames" ("id");
    CREATE INDEX 'filenames_filename' ON "filenames" ("filename");
    CREATE INDEX 'allow_cols' ON "allow" ("source", "target", "class");
    CREATE INDEX 'type_tran_cols' ON "type_trans" ("source", "target", "class", "default");
    CREATE INDEX 'dontaudit_cols' ON "dontaudit" ("source", "target", "class");
""")

conn.commit()
conn.close()
