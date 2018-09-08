/*
 *-------------------------------------------------------------------------
 *
 * pgcheck
 *     a PostgreSQL app to check database data file on filesystem
 *
 * copyright (c) leapking <leapking@126.com>, 2018;
 * licence: BSD
 *
 * src/bin/pgcheck/pgcheck.c
 *
 *-------------------------------------------------------------------------
 */

#include <assert.h>
#include <time.h>
#include <sys/stat.h>

#include "pg_getopt.h"
#include "postgres.h"
#include "access/amapi.h"
#include "access/htup_details.h"
#include "access/nbtree.h"
#include "access/tupdesc.h"
#include "access/xlog.h"
#include "access/xlog_internal.h"
#include "catalog/catalog.h"
#include "catalog/pg_control.h"
#include "catalog/pg_database.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_tablespace.h"
#include "catalog/pg_inherits.h"
#include "catalog/pg_authid.h"
#include "common/controldata_utils.h"
#include "common/config_info.h"
#include "storage/checksum.h"
#include "storage/checksum_impl.h"
#include "storage/fsm_internals.h"
#include "utils/rel.h"
#include "utils/relcache.h"

#define FRONTEND 1

#define AttrDefaultRelationId       2604
#define ConstraintRelationId        2606
#define NamespaceRelationId         2615
/* only under global */
#define AuthIdRelationId            1260
#define AuthMemRelationId           1261
#define TableSpaceRelationId        1213

#define RELCACHE_INIT_FILENAME      "pg_internal.init"
#define RELCACHE_INIT_FILEMAGIC     0x573266    /* version ID value */
#define NUM_CRITICAL_SHARED_RELS    4
#define NUM_CRITICAL_SHARED_INDEXES 6
#define NUM_CRITICAL_LOCAL_RELS     4
#define NUM_CRITICAL_LOCAL_INDEXES  7

/* Database filenode map */
#define RELMAPPER_FILENAME          "pg_filenode.map"
#define RELMAPPER_FILEMAGIC         0x592717    /* version ID value */
#define MAX_MAPPINGS                62          /* 62 * 8 + 16 = 512 */
typedef struct _RelMapping
{
    Oid        mapoid;                          /* OID of a catalog */
    Oid        mapfilenode;                     /* its filenode number */
} RelMapping;
typedef struct _RelMapFile
{
    int32      magic;                           /* always RELMAPPER_FILEMAGIC */
    int32      num_mappings;                    /* number of valid RelMapping entries */
    RelMapping mappings[MAX_MAPPINGS];
    pg_crc32c  crc;                             /* CRC of all above */
    int32      pad;                             /* to make the struct size be 512 exactly */
} RelMapFile;

/* Page Block Patch */
#define MAX_MESSAGE_LEN             256
#define DEFAULT_PATCH_FILENAME      ".pgcheck.patchs"
typedef enum
{
    PA_CREATE,
    PA_UNDO,
    PA_REDO,
    PA_DELETE
} PatchAction;
typedef enum
{
    PS_INIT,
    PS_PATCHED,
    PS_UNPATCH,
    PS_DELETE
} PatchStat;
typedef struct _BlockPatch
{
    time_t     time;
    PatchStat  state;
    int32      blknum;
    int32      offset;
    int32      oldval;
    int32      newval;
    char       name[MAX_MESSAGE_LEN];
    char       file[MAXPGPATH];
} BlockPatch;

extern char *pg_strdup(const char *in);
static bool  PGPageCheckPage(char *file, PageHeader page, BlockNumber blknum);
static bool  PGPageCheckRows(char *file, PageHeader page, BlockNumber blknum);
static bool  PGPagePrintPage(char *file, PageHeader page, BlockNumber blknum);
static bool  PGPagePrintRows(char *file, PageHeader page, BlockNumber blknum);
static bool  PGPagePrintFSMPage(char *file, PageHeader page, BlockNumber blknum);
static bool  PGPagePrintVMPage(char *file, PageHeader page, BlockNumber blknum);

static char *PGTableSpaceGetSpcInfo(Oid spcid);
static bool  PGTableSpaceGetSpcPath(Oid spcOid, char *spcPath);
static void  PGRelationSpaceUsage(char *file);
static void  PGRelationCheckFile(char *file, BlockNumber blknum, bool checkmap);
static char *PGRelationGetRelName(Oid dboid, Oid reloid);
static Oid   PGRelationGetRelInfo(Oid dboid, Oid schoid, char *relname, bool showInfo, bool showUsage, Oid *reloid, Oid *spcoid);
#define PGRelationShowRelations(dboid, schoid) \
        PGRelationGetRelInfo(dboid, schoid, NULL, false, false, NULL, NULL)
#define PGRelationGetSpcIdByRelId(dboid, schoid, preloid, pspcoid) \
        PGRelationGetRelInfo(dboid, schoid, NULL, false, false, preloid, pspcoid)
#define PGRelationGetRelIdAndSpcIdByName(dboid, schoid, relname, preloid, pspcoid) \
        PGRelationGetRelInfo(dboid, schoid, relname, false, false, preloid, pspcoid)
#define PGRelationShowRelInfoByRelId(dboid, schoid, preloid, showUsage) \
        PGRelationGetRelInfo(dboid, schoid, NULL, true, showUsage, preloid, NULL)
#define PGRelationShowRelInfoByRelName(dboid, schoid, relname, showUsage) \
        PGRelationGetRelInfo(dboid, schoid, relname, true, showUsage, 0, NULL)
#define pg_debug(fmt, args...) do { \
    if (prgm_debug) \
        pg_log(DEBUG1, "%s: " fmt, __FUNCTION__, ##args); \
    } while(0)

#define PGOPT_CHECKPAGE 0
#define PGOPT_PRINTPAGE 1
#define PGOPT_PRINTUPLE 2
bool (*PGPageOpt[][3])(char*, PageHeader, BlockNumber) = {
{PGPageCheckRows, PGPageCheckPage, PGPageCheckPage},
{PGPagePrintPage, PGPagePrintFSMPage, PGPagePrintVMPage},
{PGPagePrintRows, PGPagePrintFSMPage, PGPagePrintVMPage}};

TransactionId    OldestXmin;
ControlFileData *ControlFile = NULL;
const char      *ProgramName = NULL;
char            *PGDataDir = NULL;
char  MyExecPath[MAXPGPATH];
bool  prgm_debug = false;                            /* are we debugging? */
bool  ShowAll = false;
int   quiet_mode = 0;
int   all_yes = 0;
int   all_no = 0;
int   bopt = 0;
int   copt = 0;
int   lopt = 0;
int   popt = 0;
int   cflag = 0;
int   Cflag = 0;
int   dflag = 0;
int   Dflag = 0;
int   gflag = 0;
int   iflag = 0;
int   Iflag = 0;
int   kflag = 0;
int   Kflag = 0;
int   lflag = 0;
int   mflag = 0;
int   pflag = 0;
int   Pflag = 0;
int   rflag = 0;
int   sflag = 0;
int   tflag = 0;
int   Tflag = 0;
int   uflag = 0;
int   vflag = 0;
int   xflag = 0;
char  CheckTodo[100];
char  CheckArgs[100];
#define PGCHECK_VERSION "2.0"

static void
PGCheckPrintHeader(char *file, char* purpose)
{
    time_t now = time(NULL);

    printf("*******************************************************************\n");
    printf(" PostgreSQL Check Database File Utility - Version %-14s\n", PGCHECK_VERSION);
    printf(" Args: %s\n", CheckArgs);
    if (purpose)
        printf(" To:   %s\n", purpose);
    if (file)
        printf(" File: %s\n", file);
    printf(" Time: %-15s\n", ctime(&now));
    printf("*******************************************************************\n");
}

static void
AskToContinue()
{
    char ask=0;

    if (all_yes)
        return;
    else if (all_no)
        exit(1);

    printf("ERROR found, continue[y/n]?");
    while(1)
    {
        ask = getchar();
        if (ask == '\n')
            continue;
        if (ask == 'y')
            break;
        if (ask == 'n')
            exit(1);
        printf("ERROR found, continue[y/n]?");
    }
}

static void
pg_log(int type, const char *fmt,...)
{
    va_list args;
    char message[MAX_MESSAGE_LEN];

    va_start(args, fmt);

    vsnprintf(message, sizeof(message), _(fmt), args);
    switch (type)
    {
        case DEBUG1:
            if (prgm_debug)
                printf("%s", message);
            break;
        case WARNING:
            printf("%s", message);
            break;
        case FATAL:
            printf("\n%s", message);
            printf("%s", _("Failure, exiting\n"));
            exit(1);
            break;
        default:
            break;
    }
    fflush(stdout);

    va_end(args);
}

/*
 * ShowHexData
 *     Show raw data in hex format
 * Args:
 *    data[IN]  - data to print
 *    len[IN]   - the length of data
 */
static void
ShowHexData(const void *data, int32 len)
{
    unsigned char *c = (unsigned char *)data;
    uint32 i, num_zero_line=0;

    if (!data || len <= 0)
    {
        printf("null\n");
        return;
    }

    while(len > 0)
    {
        if (!ShowAll)
        {
            if (*(int32 *)(c) == 0 && *(int32 *)(c+4) == 0 &&
                *(int32 *)(c+8) == 0 && *(int32 *)(c+12) == 0)
            {
                num_zero_line++;
                if (num_zero_line > 1)
                {
                    if (num_zero_line == 2)
                        printf("*\n");
                    goto next;
                }
            }else
                num_zero_line = 0;
        }

        printf("%08x:", c - (unsigned char *)data);

        /* print data in hex type */
        for (i = 0; i < 16; i++)
        {
            if (i % 8 == 0)
                printf(" ");
            if (i < len)
                printf("%02x ", c[i]);
            else
                printf("   ");
        }

        /* print data in text type */
        printf("|");
        for (i = 0; i < 16; i++)
        {
            if (i % 8 == 0)
                printf(" ");
            if (i < len)
            {
                if (!isprint(c[i]) || (c[i] == '\t'))
                    printf(".");
                else
                    printf("%c", c[i]);
            }
            else
                printf(" ");
        }
        printf(" |\n");

next:
        c += 16;
        len -= 16;
    }
}

/*
 * get size of a file
 */
static long
GetFileSize(char *file)
{
    struct stat statbuf;

    if (stat(file, &statbuf) < 0)
        pg_log(FATAL, "could not get stat of file \"%s\" : %m\n", file);

    return statbuf.st_size / (1024*8);
}

/*
 * get size of a directory
 */
static int
GetDirSize(char *path)
{
    char   tmpath[MAXPGPATH];
    struct dirent *direntry;
    DIR   *dir;
    int    totalsize=0;
    struct stat statbuf;

    if ((dir = opendir(path)) == NULL)
    {
        pg_log(WARNING, "could not open dir \"%s\": %m", path);
        return 0;
    }
    while ((direntry = readdir(dir)) != NULL)
    {
        if (strcmp(direntry->d_name, ".") == 0 || strcmp(direntry->d_name, "..") == 0)
            continue;

        snprintf(tmpath, sizeof(tmpath), "%s/%s", path, direntry->d_name);
        if (stat(tmpath, &statbuf) < 0)
        {
            if (errno == ENOENT)
                continue;
            pg_log(WARNING, "could not stat file \"%s\": %m\n", tmpath);
        }

        if (S_ISDIR(statbuf.st_mode))
            totalsize += GetDirSize(tmpath);
        totalsize += statbuf.st_size;
    }
    return totalsize;
}

/*
 * CreateTemplateTupleDesc
 *     Create template tuple desc
 * Args:
 *     natts[IN]  - number of attributes
 *     hasoid[IN] - if tuple has oid
 */
TupleDesc
CreateTemplateTupleDesc(int natts, bool hasoid)
{
    TupleDesc  desc;
    char      *stg;
    int        attroffset;

    /*
     * sanity checks
     */
    assert(natts >= 0);

    /*
     * Allocate enough memory for the tuple descriptor, including the
     * attribute rows, and set up the attribute row pointers.
     *
     * Note: we assume that sizeof(struct tupleDesc) is a multiple of the
     * struct pointer alignment requirement, and hence we don't need to insert
     * alignment padding between the struct and the array of attribute row
     * pointers.
     *
     * Note: Only the fixed part of pg_attribute rows is included in tuple
     * descriptors, so we only need ATTRIBUTE_FIXED_PART_SIZE space per attr.
     * That might need alignment padding, however.
     */
    attroffset = sizeof(struct tupleDesc) + natts * sizeof(Form_pg_attribute);
    attroffset = MAXALIGN(attroffset);
    stg = palloc(attroffset + natts * MAXALIGN(ATTRIBUTE_FIXED_PART_SIZE));
    desc = (TupleDesc) stg;

    if (natts > 0)
    {
        Form_pg_attribute *attrs;
        int            i;

        attrs = (Form_pg_attribute *) (stg + sizeof(struct tupleDesc));
        desc->attrs = attrs;
        stg += attroffset;
        for (i = 0; i < natts; i++)
        {
            attrs[i] = (Form_pg_attribute) stg;
            stg += MAXALIGN(ATTRIBUTE_FIXED_PART_SIZE);
        }
    }
    else
        desc->attrs = NULL;

    /*
     * Initialize other fields of the tupdesc.
     */
    desc->natts = natts;
    desc->constr = NULL;
#define RECORDOID        2249
    desc->tdtypeid = RECORDOID;
    desc->tdtypmod = -1;
    desc->tdhasoid = hasoid;
    desc->tdrefcount = -1;        /* assume not reference-counted */

    return desc;
}

/*
 * PGDatabasePrintRelCacheFile
 *     Print database relation cache file info
 * Args:
 *     dboid[IN] - database oid
 */
static bool
PGDatabasePrintRelCacheFile(Oid dboid)
{
    FILE     *fp;
    Relation *rels;
    char      initfile[MAXPGPATH];
    int       relno, num_rels, max_rels, nailed_rels, nailed_indexes, magic, i;

    if (dboid)
        snprintf(initfile, sizeof(initfile), "%s/base/%d/%s", PGDataDir, dboid, RELCACHE_INIT_FILENAME);
    else
        snprintf(initfile, sizeof(initfile), "%s/global/%s", PGDataDir, RELCACHE_INIT_FILENAME);

    if ((fp = fopen(initfile, PG_BINARY_R)) == NULL)
        pg_log(FATAL, "could not open file \"%s\" for reading: %m\n", initfile);

    max_rels = 100;
    rels = (Relation *) palloc(max_rels * sizeof(Relation));
    num_rels = 0;
    nailed_rels = nailed_indexes = 0;

    /* check for correct magic number (compatible version) */
    if (fread(&magic, 1, sizeof(magic), fp) != sizeof(magic))
        goto read_failed;
    if (magic != RELCACHE_INIT_FILEMAGIC)
        goto read_failed;

    for (relno = 0;; relno++)
    {
        Size        len;
        size_t      nread;
        Relation    rel;
        Form_pg_class relForm;
        bool        has_not_null;

        /* first read the relation descriptor length */
        nread = fread(&len, 1, sizeof(len), fp);
        if (nread != sizeof(len))
        {
            if (nread == 0)
                break;            /* end of file */
            goto read_failed;
        }

        /* safety check for incompatible relcache layout */
        if (len != sizeof(RelationData))
            goto read_failed;

        /* allocate another relcache header */
        if (num_rels >= max_rels)
        {
            max_rels *= 2;
            rels = (Relation *) repalloc(rels, max_rels * sizeof(Relation));
        }

        rel = rels[num_rels++] = (Relation) palloc(len);

        /* then, read the Relation structure */
        if (fread(rel, 1, len, fp) != len)
            goto read_failed;

        /* next read the relation tuple form */
        if (fread(&len, 1, sizeof(len), fp) != sizeof(len))
            goto read_failed;

        relForm = (Form_pg_class) palloc(len);
        if (fread(relForm, 1, len, fp) != len)
            goto read_failed;

        rel->rd_rel = relForm;

        /* initialize attribute tuple forms */
        rel->rd_att = CreateTemplateTupleDesc(relForm->relnatts, relForm->relhasoids);
        rel->rd_att->tdrefcount = 1;    /* mark as refcounted */

        rel->rd_att->tdtypeid = relForm->reltype;
        rel->rd_att->tdtypmod = -1;        /* unnecessary, but... */

        /* next read all the attribute tuple form data entries */
        has_not_null = false;
        for (i = 0; i < relForm->relnatts; i++)
        {
            if (fread(&len, 1, sizeof(len), fp) != sizeof(len))
                goto read_failed;
            if (len != ATTRIBUTE_FIXED_PART_SIZE)
                goto read_failed;
            if (fread(rel->rd_att->attrs[i], 1, len, fp) != len)
                goto read_failed;

            has_not_null |= rel->rd_att->attrs[i]->attnotnull;
        }

        /* next read the access method specific field */
        if (fread(&len, 1, sizeof(len), fp) != sizeof(len))
            goto read_failed;
        if (len > 0)
        {
            rel->rd_options = palloc(len);
            if (fread(rel->rd_options, 1, len, fp) != len)
                goto read_failed;
            if (len != VARSIZE(rel->rd_options))
                goto read_failed;        /* sanity check */
        }
        else
        {
            rel->rd_options = NULL;
        }

        /* mark not-null status */
        if (has_not_null)
        {
            TupleConstr *constr = (TupleConstr *) palloc0(sizeof(TupleConstr));

            constr->has_not_null = true;
            rel->rd_att->constr = constr;
        }

        /* If it's an index, there's more to do */
        if (rel->rd_rel->relkind == RELKIND_INDEX)
        {
            Oid          *opfamily;
            Oid          *opcintype;
            RegProcedure *support;
            int16        *indoption;
            Oid          *indcollation;

            /* Count nailed indexes to ensure we have 'em all */
            if (rel->rd_isnailed)
                nailed_indexes++;

            /* next, read the pg_index tuple */
            if (fread(&len, 1, sizeof(len), fp) != sizeof(len))
                goto read_failed;

            rel->rd_indextuple = (HeapTuple) palloc(len);
            if (fread(rel->rd_indextuple, 1, len, fp) != len)
                goto read_failed;

            /* Fix up internal pointers in the tuple -- see heap_copytuple */
            rel->rd_indextuple->t_data = (HeapTupleHeader)((char *)rel->rd_indextuple + HEAPTUPLESIZE);
            rel->rd_index = (Form_pg_index) GETSTRUCT(rel->rd_indextuple);

            /*
             * Now we can fetch the index AM's API struct.  (We can't store
             * that in the init file, since it contains function pointers that
             * might vary across server executions.  Fortunately, it should be
             * safe to call the amhandler even while bootstrapping indexes.)
             */
            //InitIndexAmRoutine(rel);

            /* next, read the vector of opfamily OIDs */
            if (fread(&len, 1, sizeof(len), fp) != sizeof(len))
                goto read_failed;

            opfamily = (Oid *) palloc(len);
            if (fread(opfamily, 1, len, fp) != len)
                goto read_failed;

            rel->rd_opfamily = opfamily;

            /* next, read the vector of opcintype OIDs */
            if (fread(&len, 1, sizeof(len), fp) != sizeof(len))
                goto read_failed;

            opcintype = (Oid *) palloc(len);
            if (fread(opcintype, 1, len, fp) != len)
                goto read_failed;

            rel->rd_opcintype = opcintype;

            /* next, read the vector of support procedure OIDs */
            if (fread(&len, 1, sizeof(len), fp) != sizeof(len))
                goto read_failed;
            support = (RegProcedure *) palloc(len);
            if (fread(support, 1, len, fp) != len)
                goto read_failed;

            rel->rd_support = support;

            /* next, read the vector of collation OIDs */
            if (fread(&len, 1, sizeof(len), fp) != sizeof(len))
                goto read_failed;

            indcollation = (Oid *) palloc(len);
            if (fread(indcollation, 1, len, fp) != len)
                goto read_failed;

            rel->rd_indcollation = indcollation;

            /* finally, read the vector of indoption values */
            if (fread(&len, 1, sizeof(len), fp) != sizeof(len))
                goto read_failed;

            indoption = (int16 *) palloc(len);
            if (fread(indoption, 1, len, fp) != len)
                goto read_failed;

            rel->rd_indoption = indoption;
        }
        else
        {
            /* Count nailed rels to ensure we have 'em all */
            if (rel->rd_isnailed)
                nailed_rels++;

            assert(rel->rd_index == NULL);
            assert(rel->rd_indextuple == NULL);
            assert(rel->rd_indexcxt == NULL);
            assert(rel->rd_amroutine == NULL);
            assert(rel->rd_opfamily == NULL);
            assert(rel->rd_opcintype == NULL);
            assert(rel->rd_support == NULL);
            assert(rel->rd_supportinfo == NULL);
            assert(rel->rd_indoption == NULL);
            assert(rel->rd_indcollation == NULL);
        }

        /*
         * Rules and triggers are not saved (mainly because the internal
         * format is complex and subject to change).  They must be rebuilt if
         * needed by RelationCacheInitializePhase3.  This is not expected to
         * be a big performance hit since few system catalogs have such. Ditto
         * for RLS policy data, index expressions, predicates, exclusion info,
         * and FDW info.
         */
        rel->rd_rules = NULL;
        rel->rd_rulescxt = NULL;
        rel->trigdesc = NULL;
        rel->rd_rsdesc = NULL;
        rel->rd_indexprs = NIL;
        rel->rd_indpred = NIL;
        rel->rd_exclops = NULL;
        rel->rd_exclprocs = NULL;
        rel->rd_exclstrats = NULL;
        rel->rd_fdwroutine = NULL;

        /*
         * Reset transient-state fields in the relcache entry
         */
        rel->rd_smgr = NULL;
        if (rel->rd_isnailed)
            rel->rd_refcnt = 1;
        else
            rel->rd_refcnt = 0;
        rel->rd_indexvalid = 0;
        rel->rd_fkeylist = NIL;
        rel->rd_fkeyvalid = false;
        rel->rd_indexlist = NIL;
        rel->rd_oidindex = InvalidOid;
        rel->rd_replidindex = InvalidOid;
        rel->rd_indexattr = NULL;
        rel->rd_keyattr = NULL;
        rel->rd_idattr = NULL;
        rel->rd_createSubid = InvalidSubTransactionId;
        rel->rd_newRelfilenodeSubid = InvalidSubTransactionId;
        rel->rd_amcache = NULL;
        MemSet(&rel->pgstat_info, 0, sizeof(rel->pgstat_info));
    }

    /*
     * We reached the end of the init file without apparent problem.  Did we
     * get the right number of nailed items?  This is a useful crosscheck in
     * case the set of critical rels or indexes changes.  However, that should
     * not happen in a normally-running system, so let's bleat if it does.
     *
     * For the shared init file, we're called before client authentication is
     * done, which means that elog(WARNING) will go only to the postmaster
     * log, where it's easily missed.  To ensure that developers notice bad
     * values of NUM_CRITICAL_SHARED_RELS/NUM_CRITICAL_SHARED_INDEXES, we put
     * an assert(false) there.
     */
    if (dboid == 0)
    {
        if (nailed_rels != NUM_CRITICAL_SHARED_RELS || nailed_indexes != NUM_CRITICAL_SHARED_INDEXES)
        {
            pg_log(WARNING, "found %d nailed shared rels and %d nailed shared indexes in init file, but expected %d and %d respectively",
                   nailed_rels, nailed_indexes,
                   NUM_CRITICAL_SHARED_RELS, NUM_CRITICAL_SHARED_INDEXES);
            /* Make sure we get developers' attention about this */
            assert(false);
            /* In production builds, recover by bootstrapping the relcache */
            goto read_failed;
        }
    }
    else
    {
        if (nailed_rels != NUM_CRITICAL_LOCAL_RELS || nailed_indexes != NUM_CRITICAL_LOCAL_INDEXES)
        {
            pg_log(WARNING, "found %d nailed rels and %d nailed indexes in init file, but expected %d and %d respectively",
                   nailed_rels, nailed_indexes,
                   NUM_CRITICAL_LOCAL_RELS, NUM_CRITICAL_LOCAL_INDEXES);
            /* We don't need an assert() in this case */
            goto read_failed;
        }
    }

    /*
     * OK, all appears well.
     *
     * Now insert all the new relcache entries into the cache.
     */
    printf("Print internal cache file\n");
    printf("file: %s\n\n", initfile);
    for (relno = 0; relno < num_rels; relno++)
    {
        printf("\tcache: %s\n", RelationGetRelationName(rels[relno]));
    }

    pfree(rels);
    fclose(fp);
    return true;

    /*
     * init file is broken, so do it the hard way.  We don't bother trying to
     * free the clutter we just allocated; it's not in the relcache so it
     * won't hurt.
     */
read_failed:
    pfree(rels);
    fclose(fp);
    return false;
}

/*
 * PGDatabasePrintMappingFile
 *     Print database mapping(oid -> filenode) file info
 * Args:
 *     dboid[IN]  - database oid
 *     objoid[IN] - which obj to get, if only to get oid
 */
static Oid
PGDatabasePrintMappingFile(Oid dboid, Oid objoid)
{
    RelMapFile  relMap, *map;
    struct stat statbuf;
    char        mapfile[MAXPGPATH];
    pg_crc32c   crc;
    int         fd, size, i;
    Oid filenode = objoid;

    if (dboid)
        snprintf(mapfile, sizeof(mapfile), "%s/base/%d/%s", PGDataDir, dboid, RELMAPPER_FILENAME);
    else
        snprintf(mapfile, sizeof(mapfile), "%s/global/%s", PGDataDir, RELMAPPER_FILENAME);

    /* check file size */
    if (stat(mapfile, &statbuf) < 0)
        pg_log(FATAL, "could not open file \"%s\" for reading: %m\n", mapfile);

    size = statbuf.st_size;
    if (size != MAX_MAPPINGS * 8 + 16)
        pg_log(FATAL, "unexpected mapping file size %d, expected %d\n", size, MAX_MAPPINGS * 8 + 16);

    /* read file and get mapping info */
    if ((fd = open(mapfile, O_RDONLY | PG_BINARY, S_IRUSR | S_IWUSR)) == -1)
        pg_log(FATAL, "could not open file \"%s\" for reading: %m\n", mapfile);

    map = &relMap;
    if (read(fd, map, sizeof(RelMapFile)) != sizeof(RelMapFile))
    {
        close(fd);
        pg_log(FATAL, "could not read file \"%s\": %m\n", mapfile);
    }
    close(fd);

    /* check for correct magic number, etc */
    if (map->magic != RELMAPPER_FILEMAGIC || map->num_mappings < 0 || map->num_mappings > MAX_MAPPINGS)
        pg_log(FATAL, "relation mapping file \"%s\" contains invalid data", mapfile);

    /* verify the CRC */
    INIT_CRC32C(crc);
    COMP_CRC32C(crc, (char *)map, offsetof(RelMapFile, crc));
    FIN_CRC32C(crc);

    if (!EQ_CRC32C(crc, map->crc))
        pg_log(FATAL, "relation mapping file \"%s\" contains incorrect checksum", mapfile);

    if (objoid > 0)
    {
        for (i = 0; i < MAX_MAPPINGS; i++)
        {
            if (map->mappings[i].mapoid == objoid)
            {
                filenode = map->mappings[i].mapfilenode;
                break;
            }
        }
    }
    else
    {
        printf("Print relation mapping file\n");
        printf("file: %s\n\n", mapfile);
        printf("\tmapping oid to filenode for system table\n\n");
        printf("\tOid -> Filenode\n");
        for (i = 0; i < MAX_MAPPINGS; i++)
        {
            if (map->mappings[i].mapoid)
                printf("\t%d -> %d\n", map->mappings[i].mapoid, map->mappings[i].mapfilenode);
        }
        printf("\tTotal: %d\n", i);
    }
    return filenode;
}

/*
 * Print install and build info
 */
static void
PGGlobalPrintInstallAndBuildInfo(void)
{
    int i;
    ConfigData *configdata;
    size_t      configdata_len;

    printf("Print global install&build info\n");
    configdata = get_configdata(MyExecPath, &configdata_len);
    for (i = 0; i < configdata_len; i++)
        printf("\t%-20s %s\n", configdata[i].name, configdata[i].setting);
    printf("\n");
}

static const char *
PGGLobalGetDBState(DBState state)
{
    switch (state)
    {
        case DB_STARTUP:
            return _("starting up");
        case DB_SHUTDOWNED:
            return _("shut down");
        case DB_SHUTDOWNED_IN_RECOVERY:
            return _("shut down in recovery");
        case DB_SHUTDOWNING:
            return _("shutting down");
        case DB_IN_CRASH_RECOVERY:
            return _("in crash recovery");
        case DB_IN_ARCHIVE_RECOVERY:
            return _("in archive recovery");
        case DB_IN_PRODUCTION:
            return _("in production");
    }
    return _("unrecognized status code");
}

static const char *
PGGlobalGetWalLevel(WalLevel wal_level)
{
    switch (wal_level)
    {
        case WAL_LEVEL_MINIMAL:
            return "minimal";
        case WAL_LEVEL_REPLICA:
            return "replica";
        case WAL_LEVEL_LOGICAL:
            return "logical";
    }
    return _("unrecognized wal_level");
}

/*
 * PGGlobalPrintCtrlFile
 *     Print global control file
 * Args:
 *     ctrlfile[IN]  - control file content
 */
static void
PGGlobalPrintCtrlFile(ControlFileData *ctrlfile)
{
    time_t      time_tmp;
    char        pgctime_str[128];
    char        ckpttime_str[128];
    char        sysident_str[32];
    const char *strftime_fmt = "%c";
    XLogSegNo   segno;
    char        xlogfile[MAXFNAMELEN];

    if (ctrlfile == NULL)
        return;

    /*
     * This slightly-chintzy coding will work as long as the control file
     * timestamps are within the range of time_t; that should be the case in
     * all foreseeable circumstances, so we don't bother importing the
     * backend's timezone library into pgcheck.
     *
     * Use variable for format to suppress overly-anal-retentive gcc warning
     * about %c
     */
    time_tmp = (time_t)ctrlfile->time;
    strftime(pgctime_str, sizeof(pgctime_str), strftime_fmt, localtime(&time_tmp));
    time_tmp = (time_t)ctrlfile->checkPointCopy.time;
    strftime(ckpttime_str, sizeof(ckpttime_str), strftime_fmt, localtime(&time_tmp));

    /*
     * Calculate name of the WAL file containing the latest checkpoint's REDO
     * start point.
     */
    XLByteToSeg(ctrlfile->checkPointCopy.redo, segno);
    XLogFileName(xlogfile, ctrlfile->checkPointCopy.ThisTimeLineID, segno);

    /*
     * Format system_identifier separately to keep platform-dependent format
     * code out of the translatable message string.
     */
    snprintf(sysident_str, sizeof(sysident_str), UINT64_FORMAT, ctrlfile->system_identifier);
    printf(_("Print global control file\n"));
    printf(_("file: %s/%s\n\n"), PGDataDir, XLOG_CONTROL_FILE);
    printf(_("\t1. Base Info...\n\n"));
    printf(_("\tDatabase system identifier            %s\n"), sysident_str);
    printf(_("\tDatabase cluster state                %s\n"), PGGLobalGetDBState(ctrlfile->state));
    printf(_("\tCatalog version number                %u\n"), ctrlfile->catalog_version_no);
    printf(_("\tpg_control version number             %u\n"), ctrlfile->pg_control_version);
    printf(_("\tpg_control last modified              %s\n"), pgctime_str);

    printf(_("\n\t2. Checkpoint Info...\n\n"));
    printf(_("\tPrior  checkpoint's location          %X/%X\n"),
           (uint32) (ctrlfile->prevCheckPoint >> 32),
           (uint32) ctrlfile->prevCheckPoint);
    printf(_("\tLatest checkpoint's location          %X/%X\n"),
           (uint32) (ctrlfile->checkPoint >> 32),
           (uint32) ctrlfile->checkPoint);
    printf(_("\tLatest checkpoint's REDO location     %X/%X\n"),
           (uint32) (ctrlfile->checkPointCopy.redo >> 32),
           (uint32) ctrlfile->checkPointCopy.redo);
    printf(_("\tLatest checkpoint's REDO WAL file     %s\n"), xlogfile);
    printf(_("\tLatest checkpoint's PrevTimeLineID    %u\n"), ctrlfile->checkPointCopy.PrevTimeLineID);
    printf(_("\tLatest checkpoint's TimeLineID        %u\n"), ctrlfile->checkPointCopy.ThisTimeLineID);
    printf(_("\tLatest checkpoint's full_page_writes  %s\n"),
           ctrlfile->checkPointCopy.fullPageWrites ? _("on") : _("off"));
    printf(_("\tLatest checkpoint's NextXID           %u:%u\n"),
           ctrlfile->checkPointCopy.nextXidEpoch,
           ctrlfile->checkPointCopy.nextXid);
    printf(_("\tLatest checkpoint's NextOID           %u\n"), ctrlfile->checkPointCopy.nextOid);
    printf(_("\tLatest checkpoint's NextMultiXactId   %u\n"), ctrlfile->checkPointCopy.nextMulti);
    printf(_("\tLatest checkpoint's NextMultiOffset   %u\n"), ctrlfile->checkPointCopy.nextMultiOffset);
    printf(_("\tLatest checkpoint's oldestXID         %u\n"), ctrlfile->checkPointCopy.oldestXid);
    printf(_("\tLatest checkpoint's oldestXID's DB    %u\n"), ctrlfile->checkPointCopy.oldestXidDB);
    printf(_("\tLatest checkpoint's oldestActiveXID   %u\n"), ctrlfile->checkPointCopy.oldestActiveXid);
    printf(_("\tLatest checkpoint's oldestMultiXid    %u\n"), ctrlfile->checkPointCopy.oldestMulti);
    printf(_("\tLatest checkpoint's oldestMulti's DB  %u\n"), ctrlfile->checkPointCopy.oldestMultiDB);
    printf(_("\tLatest checkpoint's oldestCommitTsXid %u\n"), ctrlfile->checkPointCopy.oldestCommitTsXid);
    printf(_("\tLatest checkpoint's newestCommitTsXid %u\n"), ctrlfile->checkPointCopy.newestCommitTsXid);
    printf(_("\tLatest checkpoint's time              %s\n"), ckpttime_str);

    printf(_("\n\t3. Backupp & Restore Info...\n\n"));
    printf(_("\tFake LSN counter for unlogged rels    %X/%X\n"),
           (uint32) (ctrlfile->unloggedLSN >> 32), (uint32) ctrlfile->unloggedLSN);
    printf(_("\tMinimum recovery ending location      %X/%X\n"),
           (uint32) (ctrlfile->minRecoveryPoint >> 32),
           (uint32) ctrlfile->minRecoveryPoint);
    printf(_("\tMin recovery ending loc's timeline    %u\n"), ctrlfile->minRecoveryPointTLI);
    printf(_("\tBackup start location                 %X/%X\n"),
           (uint32) (ctrlfile->backupStartPoint >> 32),
           (uint32) ctrlfile->backupStartPoint);
    printf(_("\tBackup end location                   %X/%X\n"),
           (uint32) (ctrlfile->backupEndPoint >> 32),
           (uint32) ctrlfile->backupEndPoint);
    printf(_("\tEnd-of-backup record required         %s\n"), ctrlfile->backupEndRequired ? _("yes") : _("no"));
    printf(_("\twal_level setting                     %s\n"), PGGlobalGetWalLevel(ctrlfile->wal_level));
    printf(_("\twal_log_hints setting                 %s\n"), ctrlfile->wal_log_hints ? _("on") : _("off"));

    printf(_("\n\t4. System Other Info...\n\n"));
    printf(_("\tmax_connections setting               %d\n"), ctrlfile->MaxConnections);
    printf(_("\tmax_worker_processes setting          %d\n"), ctrlfile->max_worker_processes);
    printf(_("\tmax_prepared_xacts setting            %d\n"), ctrlfile->max_prepared_xacts);
    printf(_("\tmax_locks_per_xact setting            %d\n"), ctrlfile->max_locks_per_xact);
    printf(_("\ttrack_commit_timestamp setting        %s\n"), ctrlfile->track_commit_timestamp ? _("on") : _("off"));
    printf(_("\tMaximum data alignment                %u\n"), ctrlfile->maxAlign);
    /* we don't print floatFormat since can't say much useful about it */
    printf(_("\tDatabase block size                   %u\n"), ctrlfile->blcksz);
    printf(_("\tBlocks per segment of large relation  %u\n"), ctrlfile->relseg_size);
    printf(_("\tWAL block size                        %u\n"), ctrlfile->xlog_blcksz);
    printf(_("\tBytes per WAL segment                 %u\n"), ctrlfile->xlog_seg_size);
    printf(_("\tMaximum length of identifiers         %u\n"), ctrlfile->nameDataLen);
    printf(_("\tMaximum columns in an index           %u\n"), ctrlfile->indexMaxKeys);
    printf(_("\tMaximum size of a TOAST chunk         %u\n"), ctrlfile->toast_max_chunk_size);
    printf(_("\tSize of a large-object chunk          %u\n"), ctrlfile->loblksize);
    printf(_("\tDate/time type storage                %s\n"), (ctrlfile->enableIntTimes ? _("64-bit integers") : _("floating-point numbers")));
    printf(_("\tFloat4 argument passing               %s\n"), (ctrlfile->float4ByVal ? _("by value") : _("by reference")));
    printf(_("\tFloat8 argument passing               %s\n"), (ctrlfile->float8ByVal ? _("by value") : _("by reference")));
    printf(_("\tData page checksum version            %u\n"), ctrlfile->data_checksum_version);
    printf("\n");
}

static void
PGGlobalDataStructInfo(void)
{
    printf("PostgreSQL database data struct:\n");
    printf("data\n");
    printf("├── base                  # use to store database file(SELECT oid, datname FROM pg_database;)\n");
    printf("│   ├── 1                 # template database\n");
    printf("│   ├── 12406             # template0 database\n");
    printf("│   ├── 12407             # postgres database\n");
    printf("│   └── 16384             # testdb, first user database(select oid,relname,relfilenode from pg_class where relkind='r' and relfilenode>0 order by oid;)\n");
    printf("├── global                # under global, all the filenode is hard-code(select oid,relname,relfilenode from pg_class where relfilenode=0 order by oid;)\n");
    printf("│   ├── 1136              # pg_pltemplate\n");
    printf("│   ├── 1137              # pg_pltemplate_name_index\n");
    printf("│   ├── 1213              # pg_tablespace\n");
    printf("│   ├── 1214              # pg_shdepend\n");
    printf("│   ├── 1232              # pg_shdepend_depender_index\n");
    printf("│   ├── 1233              # pg_shdepend_reference_index\n");
    printf("│   ├── 1260              # pg_authid\n");
    printf("│   ├── 1261              # pg_auth_members\n");
    printf("│   ├── 1262              # pg_database\n");
    printf("│   ├── 2396              # pg_shdescription\n");
    printf("│   ├── 2397              # pg_shdescription_o_c_index\n");
    printf("│   ├── 2671              # pg_database_datname_index\n");
    printf("│   ├── 2672              # pg_database_oid_index\n");
    printf("│   ├── 2676              # pg_authid_rolname_index\n");
    printf("│   ├── 2677              # pg_authid_oid_index\n");
    printf("│   ├── 2694              # pg_auth_members_role_member_index\n");
    printf("│   ├── 2695              # pg_auth_members_member_role_index\n");
    printf("│   ├── 2697              # pg_tablespace_oid_index\n");
    printf("│   ├── 2698              # pg_tablespace_spcname_index\n");
    printf("│   ├── 2846              # pg_toast_2396\n");
    printf("│   ├── 2847              # pg_toast_2396_index\n");
    printf("│   ├── 2964              # pg_db_role_setting\n");
    printf("│   ├── 2965              # pg_db_role_setting_databaseid_rol_index\n");
    printf("│   ├── 2966              # pg_toast_2964\n");
    printf("│   ├── 2967              # pg_toast_2964_index\n");
    printf("│   ├── 3592              # pg_shseclabel\n");
    printf("│   ├── 3593              # pg_shseclabel_object_index\n");
    printf("│   ├── 4060              # pg_toast_3592x\n");
    printf("│   ├── 4061              # pg_toast_3592_index\n");
    printf("│   ├── 6000              # pg_replication_origin\n");
    printf("│   ├── 6001              # pg_replication_origin_roiident_index\n");
    printf("│   ├── 6002              # pg_replication_origin_roname_index\n");
    printf("│   ├── pg_control        # global control file, use pgcheck -pc to see it.\n");
    printf("│   ├── pg_filenode.map   # system table (oid -> filenode) mapping file, use pgcheck -pm to see it.\n");
    printf("│   └── pg_internal.init  # system table cache file, use pgcheck -pr to see it.\n");
    printf("├── pg_clog               # dir of transaction commit log\n");
    printf("│   └── 0000\n");
    printf("├── pg_commit_ts\n");
    printf("├── pg_dynshmem\n");
    printf("├── pg_hba.conf           # client authentication config file\n");
    printf("├── pg_ident.conf         # user ident map file\n");
    printf("├── pg_logical\n");
    printf("│   ├── mappings\n");
    printf("│   └── snapshots\n");
    printf("├── pg_multixact\n");
    printf("│   ├── members\n");
    printf("│   │   └── 0000\n");
    printf("│   └── offsets\n");
    printf("│       └── 0000\n");
    printf("├── pg_notify\n");
    printf("│   └── 0000\n");
    printf("├── pg_replslot\n");
    printf("├── pg_serial\n");
    printf("├── pg_snapshots         # dir of snapshot file\n");
    printf("├── pg_stat\n");
    printf("├── pg_stat_tmp          # dir of tmp stat file\n");
    printf("│   ├── db_0.stat\n");
    printf("│   ├── db_12407.stat\n");
    printf("│   ├── db_16384.stat\n");
    printf("│   └── global.stat\n");
    printf("├── pg_subtrans\n");
    printf("│   └── 0000\n");
    printf("├── pg_tblspc\n");
    printf("├── pg_twophase\n");
    printf("├── PG_VERSION           # version file\n");
    printf("├── pg_xlog              # dir of xlog file\n");
    printf("│   ├── 000000010000000000000001\n");
    printf("│   └── archive_status   # status info of xlog archive\n");
    printf("├── postgresql.auto.conf\n");
    printf("├── postgresql.conf      # config file of postmaster progress\n");
    printf("├── postmaster.opts\n");
    printf("└── postmaster.pid       # pid file of postmaster progress\n");
    exit(0);
}

/*
 * PGGlobalGetXLogFiles
 *     Print xlog files
 * Args:
 *     ctrlfile[IN]  - control file content
 */
static void
PGGlobalGetXLogFiles(ControlFileData *ctrlfile)
{
    char cmd_lsxlog[MAXPGPATH];

    snprintf(cmd_lsxlog, sizeof(cmd_lsxlog), "ls -l %s/pg_xlog | grep '^[-r]' | awk '{print $9\" \"$5/1024\"KB\"}'", PGDataDir);
    system(cmd_lsxlog);
}

/*
 * PGPageCheckPage
 *     Check page if is valid
 * while initdb add param"-k or --data-checksums" to enable checksum on all page.
 * Args:
 *     file[IN]   - file to read
 *     page[IN]   - page data
 *     blknum[IN] - the pos of page in file
 */
static bool
PGPageCheckPage(char *file, PageHeader page, BlockNumber blknum)
{
    if (PageIsNew(page))
    {
        int   i;
        char *pagebytes = (char *)page;

        /* Check all-zeroes case */
        for (i = 0; i < BLCKSZ; i++)
        {
            if (pagebytes[i] != 0)
            {
                pg_log(WARNING, "file:%s, block:%d is invalid, new page is not all-zeroes\n", file, blknum);
                goto page_bad;
            }
        }
        goto page_good;
    }

    if ((page->pd_flags & ~PD_VALID_FLAG_BITS) != 0 ||
        PageGetPageSize(page) < SizeOfPageHeaderData ||
        page->pd_lower < SizeOfPageHeaderData ||
        page->pd_lower > page->pd_upper ||
        page->pd_upper > page->pd_special ||
        page->pd_special > BLCKSZ ||
        page->pd_special < SizeOfPageHeaderData ||
        page->pd_special != MAXALIGN(page->pd_special))
    {
        pg_log(WARNING, "file:%s, block:%d is invalid, bad page header\n", file, blknum);
        goto page_bad;
    }

    if ((ControlFile && ControlFile->data_checksum_version > 0) && page->pd_checksum != pg_checksum_page((char *)page, blknum))
    {
        pg_log(WARNING, "file:%s, block:%d is invalid, bad page checksum\n", file, blknum);
        goto page_bad;
    }

page_good:
    return true;

page_bad:
    AskToContinue();
    return false;
}

/*
 * PGPageCheckRows
 *     Check rows in current page
 * Args:
 *     file[IN]   - file to read
 *     page[IN]   - page data
 *     blknum[IN] - the pos of page in file
 */
static bool
PGPageCheckRows(char *file, PageHeader page, BlockNumber blknum)
{
    int    off;
    OffsetNumber maxoff = InvalidOffsetNumber;
    ItemId itemid;
    HeapTupleHeader tuphdr;

    PGPageCheckPage(file, page, blknum);
    maxoff = PageGetMaxOffsetNumber(page);
    if (maxoff == InvalidOffsetNumber)
    {
        pg_log(WARNING, "file:%s, block:%d is invalid, bad max offsetnumber:%d\n", file, blknum, maxoff);
        goto row_bad;
    }

    for (off = FirstOffsetNumber; off <= maxoff; off++)
    {
        itemid = PageGetItemId(page, off);
        if (!ItemIdIsValid(itemid))
        {
            pg_log(WARNING, "file:%s, block:%d, item:%d is invalid, bad ItemId\n", file, blknum, off);
            goto row_bad;
        }
        if (itemid->lp_len == 0)
            continue;

        tuphdr = (HeapTupleHeader) PageGetItem(page, itemid);
        if (HeapTupleHeaderXminInvalid(tuphdr))
        {
            pg_log(WARNING, "file:%s, block:%d, item:%d is invalid, bad xmin\n", file, blknum, off);
            goto row_bad;
        }

        if (!ItemPointerIsValid(&tuphdr->t_ctid))
        {
            pg_log(WARNING, "file:%s, block:%d, item:%d is invalid, bad item pointer\n", file, blknum, off);
            goto row_bad;
        }
    }
    return true;

row_bad:
    AskToContinue();
    return false;
}

/*
 * PGPagePrintFSMPage
 *     Print page info
 * Args:
 *     file[IN]   - file to read
 *     page[IN]   - page data
 *     blknum[IN] - the pos of page in file
 */
static bool
PGPagePrintFSMPage(char *file, PageHeader page, BlockNumber blknum)
{
    int        i;
    FSMPage    map;
    XLogRecPtr lsn;

    PGPageCheckPage(file, page, blknum);
    printf("\nBlock: %d\n", blknum);
    printf("=================================================================================\n");
    printf("lsn\t\tchksum\tflags\tlower\tupper\tspecial\tsize\tversion\tprune_xid\n");
    lsn = PageGetLSN(page);
    printf("%X/%X\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\n",
           (uint32) (lsn >> 32), (uint32) lsn,
           UInt16GetDatum(page->pd_checksum),
           UInt16GetDatum(page->pd_flags),
           UInt16GetDatum(page->pd_lower),
           UInt16GetDatum(page->pd_upper),
           UInt16GetDatum(page->pd_special),
           UInt16GetDatum(PageGetPageSize(page)),
           UInt16GetDatum(PageGetPageLayoutVersion(page)),
           TransactionIdGetDatum(page->pd_prune_xid));
    printf("---------------------------------------------------------------------------------\n");
    map = (FSMPage) PageGetContents(page);
    printf("fp_next_slot=%d\n", map->fp_next_slot);
    for (i = 0; i < NodesPerPage; i++)
    {
        printf("fp_nodes=%d ", map->fp_nodes[i]);
    }
    printf("---------------------------------------------------------------------------------\n");
    printf("\n");
    return true;
}

/*
 * PGPagePrintVMPage
 *     Print page info
 * Args:
 *     file[IN]   - file to read
 *     page[IN]   - page data
 *     blknum[IN] - the pos of page in file
 */
static bool
PGPagePrintVMPage(char *file, PageHeader page, BlockNumber blknum)
{
    FSMPage    map;
    XLogRecPtr lsn;

    PGPageCheckPage(file, page, blknum);
    printf("\nBlock: %d\n", blknum);
    printf("=================================================================================\n");
    printf("lsn\t\tchksum\tflags\tlower\tupper\tspecial\tsize\tversion\tprune_xid\n");
    lsn = PageGetLSN(page);
    printf("%X/%X\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\n",
           (uint32) (lsn >> 32), (uint32) lsn,
           UInt16GetDatum(page->pd_checksum),
           UInt16GetDatum(page->pd_flags),
           UInt16GetDatum(page->pd_lower),
           UInt16GetDatum(page->pd_upper),
           UInt16GetDatum(page->pd_special),
           UInt16GetDatum(PageGetPageSize(page)),
           UInt16GetDatum(PageGetPageLayoutVersion(page)),
           TransactionIdGetDatum(page->pd_prune_xid));
    printf("---------------------------------------------------------------------------------\n");
    map = (FSMPage) PageGetContents(page);
    ShowHexData((char *)map, PageGetPageSize(page) - MAXALIGN(SizeOfPageHeaderData));
    printf("---------------------------------------------------------------------------------\n");
    printf("\n");
    return true;
}

/*
 * PGPagePrintPage
 *     Print page info
 * Args:
 *     file[IN]   - file to read
 *     page[IN]   - page data
 *     blknum[IN] - the pos of page in file
 */
static bool
PGPagePrintPage(char *file, PageHeader page, BlockNumber blknum)
{
    int          off;
    OffsetNumber maxoff = InvalidOffsetNumber;
    XLogRecPtr   lsn;
    ItemId       itemid;
    char         flags[10];

	/* 1. check page header */
    PGPageCheckPage(file, page, blknum);

	/* 2. show page header */
    printf("\nBlockId: %d, Offset: 0x%08x\n", blknum, blknum*ControlFile->blcksz);
    printf("=================================================================================\n");
    printf("lsn       chksum flags  lower upper special size vers xid\n");
    lsn = PageGetLSN(page);
    printf("%X/%X %-6u 0x%-4X %-5u %-5u %-7u %-4u %-5u %-u\n",
           (uint32) (lsn >> 32), (uint32) lsn,
           UInt16GetDatum(page->pd_checksum),
           UInt16GetDatum(page->pd_flags),
           UInt16GetDatum(page->pd_lower),
           UInt16GetDatum(page->pd_upper),
           UInt16GetDatum(page->pd_special),
           UInt16GetDatum(PageGetPageSize(page)),
           UInt16GetDatum(PageGetPageLayoutVersion(page)),
           TransactionIdGetDatum(page->pd_prune_xid));
    printf("---------------------------------------------------------------------------------\n");
    printf("\n");

	/* 3. show items */
    printf("\titem\toff\tlen\tflags\n");
    maxoff = PageGetMaxOffsetNumber(page);
    for (off = FirstOffsetNumber; off <= maxoff; off++)
    {
        itemid = PageGetItemId(page, off);
        switch(itemid->lp_flags)
        {
            case LP_UNUSED:
                strcpy(flags, "UNUSED");
                break;
            case LP_NORMAL:
                strcpy(flags, "NORMAL");
                break;
            case LP_REDIRECT:
                strcpy(flags, "REDIRECT");
                break;
            case LP_DEAD:
                strcpy(flags, "DEAD");
                break;
            default:
                strcpy(flags, "UNKNOWN");
                break;
        }
        printf("\t%d\t%d\t%d\t%d(%s)\n", off, itemid->lp_off, itemid->lp_len, itemid->lp_flags, flags);
    }
    for (off = FirstOffsetNumber; off <= maxoff; off++)
    {
        itemid = PageGetItemId(page, off);
        switch(itemid->lp_flags)
        {
            case LP_UNUSED:
                strcpy(flags, "UNUSED");
                break;
            case LP_NORMAL:
                strcpy(flags, "NORMAL");
                break;
            case LP_REDIRECT:
                strcpy(flags, "REDIRECT");
                break;
            case LP_DEAD:
                strcpy(flags, "DEAD");
                break;
            default:
                strcpy(flags, "UNKNOWN");
                break;
        }
        printf("\nitem[%d] -> offset:%d, len:%d, flag:%d[%s]\n",
                off, maxoff,
                itemid->lp_off, itemid->lp_len, itemid->lp_flags, flags);
        ShowHexData((char *) page + itemid->lp_off, itemid->lp_len);
    }
    printf("---------------------------------------------------------------------------------\n");
    printf("\n");
    return true;
}

/*
 * PGPagePrintPageRawData
 *     Print page data in hex format
 * Args:
 *     file[IN]   - file to read
 *     page[IN]   - page data
 *     blknum[IN] - the pos of page in file
 */
static bool
PGPagePrintPageRawData(char *file, PageHeader page, BlockNumber blknum)
{
    PGPageCheckPage(file, page, blknum);
    ShowHexData((char *)page, BLCKSZ);
    return true;
}

/*
 * PGPagePrintRows
 *     Print rows in current page
 * Args:
 *     file[IN]   - file to read
 *     page[IN]   - page data
 *     blknum[IN] - the pos of page in file
 */
static bool
PGPagePrintRows(char *file, PageHeader page, BlockNumber blknum)
{
    int    off;
    OffsetNumber maxoff = InvalidOffsetNumber;
    ItemId itemid;
    HeapTupleHeader tuphdr;

    PGPageCheckPage(file, page, blknum);
    maxoff = PageGetMaxOffsetNumber(page);
    printf("\nBlock: %d\n", blknum);
    printf("=================================================================================\n");
    for (off = FirstOffsetNumber; off <= maxoff; off++)
    {
        itemid = PageGetItemId(page, off);
        if (itemid->lp_len == 0)
            continue;
        tuphdr = (HeapTupleHeader) PageGetItem(page, itemid);
        printf("xmin\txmax\tfield3\tctid\tmask2\tmask\thoff\n");
        printf("%d\t%d\t%d\t(%u,%u)\t0x%04X\t0x%04X\t%d\n",
               HeapTupleHeaderGetRawXmin(tuphdr),
               HeapTupleHeaderGetRawXmax(tuphdr),
               HeapTupleHeaderGetRawCommandId(tuphdr),
               BlockIdGetBlockNumber(&(tuphdr->t_ctid.ip_blkid)), tuphdr->t_ctid.ip_posid,
               tuphdr->t_infomask2,
               tuphdr->t_infomask,
               tuphdr->t_hoff);

        ShowHexData((char *)page + itemid->lp_off + tuphdr->t_hoff, itemid->lp_len - tuphdr->t_hoff);
        printf("\n");
    }
    return true;
}

/*
 * PGRelationReadFile
 *     read the relation data file
 * Args:
 *     file[IN]   - file to read
 *     blknum[IN] - which block to read
 *     func[IN]   - do function for page
 * Ret: result of func
 */
static bool
PGRelationReadFile(char *file, BlockNumber blknum, bool (*func)(char*, PageHeader, BlockNumber))
{
    char        buffer[BLCKSZ];
    int         fd;
    struct stat statbuf;
    off_t       seekpos=0;
    BlockNumber blkid=(blknum == InvalidBlockNumber) ? 0 : blknum;
    bool        ret=true;

    if (stat(file, &statbuf) < 0)
    {
        printf("no file of \"%s\" : %m\n", file);
        return ret;
    }
    if (statbuf.st_size == 0)
    {
        printf("size of table file: %s is 0\n", file);
        return ret;
    }

    if ((fd = open(file, O_RDONLY | PG_BINARY, S_IRUSR | S_IWUSR)) == -1)
        pg_log(FATAL, "could not open file \"%s\" for reading: %m\n", file);

    seekpos = (off_t) BLCKSZ * blkid;
    if (lseek(fd, seekpos, SEEK_SET) != seekpos)
    {
        close(fd);
        pg_log(FATAL, "could not seek to block %u in file \"%s\"\n", blkid, file);
    }
    while (read(fd, buffer, BLCKSZ) == BLCKSZ)
    {
        ret &= (*func)(file, (PageHeader) buffer, blkid++);
        if (blknum != InvalidBlockNumber)
            break;
    }

    close(fd);
    return ret;
}

/*
 * PGClassGetObjectPath
 *     get path of a object
 * Args:
 *     spcOid[IN]   - oid of tablespace
 *     dboid[IN]    - filenode of database
 *     tbfnode[IN]  - filenode of table
 *     objPath[OUT] - path of object
 */
static void
PGClassGetObjectPath(Oid spcOid, Oid dboid, Oid tbfnode, char *objPath)
{
    if (!PGTableSpaceGetSpcPath(spcOid, objPath))
        return;

    if (dboid)
        snprintf(objPath+strlen(objPath), MAXPGPATH, "/%d", dboid);
    if (tbfnode)
        snprintf(objPath+strlen(objPath), MAXPGPATH, "/%d", tbfnode);
}

static void
PGRelationGetIndexPgeType(uint16 flag)
{
    if (flag & BTP_ROOT)
        printf("ROOT");
    if (flag & BTP_LEAF)
        printf("LEAF");
    if (flag & BTP_DELETED)
        printf("DELETED");
    if (flag & BTP_META)
        printf("META");
    if (flag & BTP_HALF_DEAD)
        printf("HALF_DEAD");
    if (flag & BTP_SPLIT_END)
        printf("SPLIT_END");
    if (flag & BTP_HAS_GARBAGE)
        printf("HAS_GARBAGE");
    if (flag & BTP_INCOMPLETE_SPLIT)
        printf("INCOMPLETE_SPLIT");
}

static void
PGRelationShowIndexBTree(char *file, BlockNumber blknum, bool pageinfo)
{
    char            buffer[BLCKSZ];
    int             fd, off;
    BlockNumber     blkid=(blknum == InvalidBlockNumber) ? 1 : blknum;
    OffsetNumber    maxoff = InvalidOffsetNumber;
    ItemId          itemid;
    IndexTuple      tuple;
    BTPageOpaque    opaque;
    BTMetaPageData *metad;
    uint64          total_live=0, total_dead=0, total_size=0, total_free=0;
    off_t           seekpos=0;

    if ((fd = open(file, O_RDONLY | PG_BINARY, S_IRUSR | S_IWUSR)) == -1)
        pg_log(FATAL, "could not open file \"%s\" for reading: %m\n", file);

    /* read meta page */
    if (read(fd, buffer, BLCKSZ) != BLCKSZ)
        pg_log(FATAL, "could not read file \"%s\": %m\n", file);

    metad = BTPageGetMeta((Page)buffer);
    if (metad->btm_magic != BTREE_MAGIC)
        pg_log(FATAL, "file: \"%s\" is not btree file\n", file);

    printf("Meta Page:\n");
    printf("-----------------------------------------------------------------\n");
    printf("magic    \tversion\troot\tlevel\tfastroot\tfastlevel\n");
    printf("0x%08x\t%d\t%d\t%d\t%-8d\t%d\n", metad->btm_magic, metad->btm_version,
            metad->btm_root, metad->btm_level, metad->btm_fastroot, metad->btm_fastlevel);
    if (blknum == 0)
        return;

    seekpos = (off_t) BLCKSZ * blkid;
    if (lseek(fd, seekpos, SEEK_SET) != seekpos)
    {
        close(fd);
        pg_log(FATAL, "could not seek to block %u in file \"%s\"\n", blkid, file);
    }
    while (read(fd, buffer, BLCKSZ) == BLCKSZ)
    {
        float avg_item_size=0;
        int item_size=0, live_items=0, dead_items=0;
        Page        page = (Page)buffer;
        PageHeader  phdr = (PageHeader) page;

        /* count live and dead tuples, and total item size */
        maxoff = PageGetMaxOffsetNumber(page);
        for (off = FirstOffsetNumber; off <= maxoff; off++)
        {
            itemid = PageGetItemId(page, off);
            tuple = (IndexTuple) PageGetItem(page, itemid);

            item_size += IndexTupleSize(tuple);
            if (!ItemIdIsDead(itemid))
                live_items++;
            else
                dead_items++;
        }
        if ((live_items + dead_items) > 0)
        {
            avg_item_size = item_size / (live_items + dead_items);
        }
        total_size += PageGetPageSize(page);
        total_free += phdr->pd_upper - phdr->pd_lower - sizeof(ItemIdData);
        total_live += live_items;
        total_dead += dead_items;

        printf("\n");
        /* show page info */
        if (pageinfo)
        {
            opaque = (BTPageOpaque) PageGetSpecialPointer(page);
            printf("blkno\ttype\tlive_items\tdead_items\tavg_item_size\tpage_size\tfree_size\tbtpo_prev\tbtpo_next\tbtpo\tbtpo_flags\n");
            printf("%d\t", blkid++);
            PGRelationGetIndexPgeType(opaque->btpo_flags);
            printf("\t%-10d\t%-10d\t%f\t%-10d\t%-10d\t%-10d\t%-10d\t%-5d\t%-10d\n", live_items, dead_items, avg_item_size, 
                    PageGetPageSize(page), phdr->pd_upper - phdr->pd_lower - sizeof(ItemIdData), 
                    opaque->btpo_prev, opaque->btpo_next, opaque->btpo.level, opaque->btpo_flags);
            printf("--------------------------------------------------------------------------------------------------------------------------------------------------\n");
        }

        /* show page data */
        printf("\toffset\tctid\tlen\tnulls\tvars\tdata\n");
        maxoff = PageGetMaxOffsetNumber(page);
        for (off = FirstOffsetNumber; off <= maxoff; off++)
        {
            itemid = PageGetItemId(page, off);
            tuple = (IndexTuple) PageGetItem(page, itemid);

            printf("\t%d\t(%u,%u)\t%d\t%c\t%c\t", off, 
                    BlockIdGetBlockNumber(&(tuple->t_tid.ip_blkid)), tuple->t_tid.ip_posid, (int) IndexTupleSize(tuple), 
                    IndexTupleHasNulls(tuple) ? 't' : 'f', IndexTupleHasVarwidths(tuple) ? 't' : 'f');
            ShowHexData((char *)tuple + IndexInfoFindDataOffset(tuple->t_info), IndexTupleSize(tuple) - IndexInfoFindDataOffset(tuple->t_info));
        }
        if (blknum != InvalidBlockNumber)
            break;
    }
    if (blknum == InvalidBlockNumber)
    {
        printf("----------------------------------------------------------------------------------------\n");
        printf("total_size\ttotal_free\ttotal_live\ttotal_dead\n");
        printf("%-10llu\t%-10llu\t%-10llu\t%llu\n", total_size, total_free, total_live, total_dead);
    }

    close(fd);
    return;
}

/*
 * PGAuthGetAuthInfo
 *     get auth info
 * Args:
 *     owner[IN] - oid of auth. 0: print all auth info
 * Ret: authname
 */
static char* 
PGAuthGetAuthInfo(Oid owner)
{
    char           authfile[MAXPGPATH], buffer[BLCKSZ];
    int            fd, off=0, blknum=0;
    OffsetNumber maxoff = InvalidOffsetNumber;
    ItemId         itemid;
    HeapTupleData  tuple;
    Form_pg_authid authForm;
    char          *authname = NULL;
    Oid            authoid = 0;

    snprintf(authfile, sizeof(authfile), "%s/global/%d", PGDataDir, AuthIdRelationId);
    if ((fd = open(authfile, O_RDONLY | PG_BINARY, S_IRUSR | S_IWUSR)) == -1)
        pg_log(FATAL, "could not open file \"%s\" for reading: %m\n", authfile);

    if (owner == 0)
    {
        printf("Print global auth members info:\n\n");
        printf(" oid    | rolname\n");
        printf("--------+-----------------\n");
    }
    while (read(fd, buffer, BLCKSZ) == BLCKSZ)
    {
        PGPageCheckPage(authfile, (PageHeader)buffer, blknum++);
        maxoff = PageGetMaxOffsetNumber(buffer);
        for (off = FirstOffsetNumber; off <= maxoff; off++)
        {
            itemid = PageGetItemId(buffer, off);
            tuple.t_data = (HeapTupleHeader) PageGetItem((Page)buffer, itemid);
            tuple.t_len = ItemIdGetLength(itemid);
            if (tuple.t_len <= 0 || !ItemIdIsUsed(itemid))
                continue;
            authoid = HeapTupleGetOid(&tuple);
            authForm = (Form_pg_authid) GETSTRUCT(&tuple);
            if (owner == 0)
            {
                printf(" %-6d | %-15s \n",
                       authoid, NameStr(authForm->rolname));
            }
            else if (owner == authoid)
            {
                authname = NameStr(authForm->rolname);
                goto done;
            }
        }
    }
    if (owner == 0)
        printf("(%d rows)\n", off-1);

done:
    close(fd);
    return authname;
}

/*
 * PGDatabaseGetDBInfo
 *     read pg_database file and get the oid
 * Args:
 *     dbname[IN]   - database name. null: print all database name
 *     showInfo[IN] - database detail info
 * Ret: dboid
 */
static Oid
PGDatabaseGetDBInfo(char *dbname, bool showInfo)
{
    char             datfile[MAXPGPATH], buffer[BLCKSZ];
    int              fd, off, blknum=0;
    OffsetNumber maxoff = InvalidOffsetNumber;
    Oid              dboid=0;
    ItemId           itemid;
    HeapTupleData    tuple;
    Form_pg_database datForm=NULL;

    snprintf(datfile, sizeof(datfile), "%s/global/%d", PGDataDir, DatabaseRelationId);
    if ((fd = open(datfile, O_RDONLY | PG_BINARY, S_IRUSR | S_IWUSR)) == -1)
        pg_log(FATAL, "could not open file \"%s\" for reading: %m\n", datfile);

    while (read(fd, buffer, BLCKSZ) == BLCKSZ)
    {
        PGPageCheckPage(datfile, (PageHeader)buffer, blknum++);
        maxoff = PageGetMaxOffsetNumber(buffer);
        for (off = FirstOffsetNumber; off <= maxoff; off++)
        {
            itemid = PageGetItemId(buffer, off);
            tuple.t_data = (HeapTupleHeader) PageGetItem((Page) buffer, itemid);
            tuple.t_len = ItemIdGetLength(itemid);
            if (tuple.t_len <= 0 || !ItemIdIsUsed(itemid))
                continue;

            datForm = (Form_pg_database) GETSTRUCT(&tuple);
            if (dbname == NULL)
            {
                printf("\tdatabase: %s\n", NameStr(datForm->datname));
                continue;
            }
            if (strcmp(dbname, NameStr(datForm->datname)) == 0)
            {
                dboid = HeapTupleGetOid(&tuple);
                goto done;
            }
        }
    }

done:
    close(fd);
    if (showInfo)
    {
        if (dboid && datForm)
        {
            struct stat statbuf;
            int res;
            PGClassGetObjectPath(datForm->dattablespace, dboid, 0, datfile);
            if ((res = stat(datfile, &statbuf)) < 0)
                pg_log(WARNING, "could not stat file \"%s\": %m\n", datfile);
            printf("\t%-50s %s\n", "Physical Address", datfile);
            printf("\t%-50s %ld Bytes\n", "Physical size", res ? 0 : statbuf.st_size);
            printf("\t%-50s %s", "Creation time", res ? "unknown\n" : ctime(&statbuf.st_ctime));
            printf("\t%-50s %s", "Last modify time", res ? "unknown\n" : ctime(&statbuf.st_mtime));
            printf("\t%-50s %s\n", "Last access time", res ? "unknown\n" : ctime(&statbuf.st_atime));
            printf("\t%-50s %d\n", "oid of the database", dboid);
            printf("\t%-50s %s\n", "name of the database", NameStr(datForm->datname));
            printf("\t%-50s %d (%s)\n", "oid of the owner", datForm->datdba, PGAuthGetAuthInfo(datForm->datdba));
            printf("\t%-50s %d\n", "character encoding", datForm->encoding);
            printf("\t%-50s %s\n", "default LC_COLLATE settings", NameStr(datForm->datcollate));
            printf("\t%-50s %s\n", "default LC_CTYPE setting", NameStr(datForm->datctype));
            printf("\t%-50s %c\n", "allowed as template?", datForm->datistemplate ? 'T' : 'F');
            printf("\t%-50s %c\n", "allowing connections?", datForm->datallowconn ? 'T' : 'F');
            printf("\t%-50s %d\n", "connection limit of the database", datForm->datconnlimit);
            printf("\t%-50s %d\n", "last system OID used in database", datForm->datlastsysoid);
            printf("\t%-50s %d\n", "limit of frozen XIDs", datForm->datfrozenxid);
            printf("\t%-50s %d\n", "minimum MultixactId", datForm->datminmxid);
            printf("\t%-50s %d (%s)\n", "default tablespace for this database", datForm->dattablespace, PGTableSpaceGetSpcInfo(datForm->dattablespace));
            //printf("\t%-50s %s\n", "default locale settings for this database", datForm->datacl);
        }
        else
            printf("Invalid oid, can not show info.\n");
    }
    return dboid;
}

/*
 * PGTableSpaceGetSpcPath
 *     get path of a table space
 * Args:
 *     spcOid[IN]   - oid of tablespace
 *     spcPath[OUT] - path of tablespace
 * Ret:
 *     true: if spcPath exist
 */
static bool
PGTableSpaceGetSpcPath(Oid spcOid, char *spcPath)
{
    char tmpath[MAXPGPATH];
    struct stat statbuf;

    if (!spcOid || spcOid == DEFAULTTABLESPACE_OID)
        snprintf(spcPath, MAXPGPATH, "%s/base", PGDataDir);
    else if (spcOid == GLOBALTABLESPACE_OID)
        snprintf(spcPath, MAXPGPATH, "%s/global", PGDataDir);
    else
    {
        int len = 0;
        snprintf(spcPath, MAXPGPATH, "%s/pg_tblspc/%u", PGDataDir, spcOid);
        if ((len = readlink(spcPath, tmpath, MAXPGPATH - 1)) != -1)
            tmpath[len] = '\0';
        snprintf(spcPath, MAXPGPATH, "%s/%s", tmpath, TABLESPACE_VERSION_DIRECTORY);
    }

    if (stat(spcPath, &statbuf) < 0)
        return false;
    return true;
}

/*
 * PGTableSpaceGetSpcInfo
 *     get table space info
 * Args:
 *     spcid[IN] - oid of tablespace. 0: print all space info
 * Ret:
 *     tablespace name
 */
static char* 
PGTableSpaceGetSpcInfo(Oid spcid)
{
    char          tbsfile[MAXPGPATH], buffer[BLCKSZ];
    int           fd, off=0, blknum=0;
    OffsetNumber maxoff = InvalidOffsetNumber;
    ItemId        itemid;
    HeapTupleData tuple;
    Form_pg_tablespace spcForm;
    char *spcname = NULL, *tblspcPath = tbsfile;
    Oid tblspcOid;

    snprintf(tbsfile, sizeof(tbsfile), "%s/global/%d", PGDataDir, TableSpaceRelationId);
    if ((fd = open(tbsfile, O_RDONLY | PG_BINARY, S_IRUSR | S_IWUSR)) == -1)
        pg_log(FATAL, "could not open file \"%s\" for reading: %m\n", tbsfile);

    if (spcid == 0)
    {
        printf("Print global table space info:\n");
        printf(" oid    | spcname         | spcowner        | size(KB)   | path\n");
        printf("--------+-----------------+-----------------+------------+---------------\n");
    }
    while (read(fd, buffer, BLCKSZ) == BLCKSZ)
    {
        PGPageCheckPage(tbsfile, (PageHeader)buffer, blknum++);
        maxoff = PageGetMaxOffsetNumber(buffer);
        for (off = FirstOffsetNumber; off <= maxoff; off++)
        {
            itemid = PageGetItemId(buffer, off);
            tuple.t_data = (HeapTupleHeader) PageGetItem((Page)buffer, itemid);
            tuple.t_len = ItemIdGetLength(itemid);
            if (tuple.t_len <= 0 || !ItemIdIsUsed(itemid))
                continue;
            tblspcOid = HeapTupleGetOid(&tuple);
            spcForm = (Form_pg_tablespace) GETSTRUCT(&tuple);
            if (spcid == 0)
            {
                if (PGTableSpaceGetSpcPath(tblspcOid, tblspcPath))
                    printf(" %-6d | %-15s | %-15s | %-10d | %s\n",
                           tblspcOid, NameStr(spcForm->spcname),
                           PGAuthGetAuthInfo(spcForm->spcowner),
                           GetDirSize(tblspcPath)/1024, tblspcPath);
            }
            else if (spcid == tblspcOid)
            {
                spcname = NameStr(spcForm->spcname);
                goto done;
            }
        }
    }
    if (spcid == 0)
        printf("(%d rows)\n", off-1);

done:
    close(fd);
    return spcname;
}

/*
 * PGNameSpaceGetSchemaInfo
 *     get name space info
 * Args:
 *     dboid[IN]       - database file node
 *     nspname[INT]    - name of namespace
 *     nspoid[INT/OUT] - oid of namespace
 *     showInfo[INT]   - if show namespace info
 * Ret:
 *     name of namespace
 */
static char* 
PGNameSpaceGetSchemaInfo(Oid dboid, char *nspname, Oid *nspoid, bool showInfo)
{
    char              nspfile[MAXPGPATH], buffer[BLCKSZ];
    int               fd, off, blknum=0;
    OffsetNumber maxoff = InvalidOffsetNumber;
    ItemId            itemid;
    HeapTupleData     tuple;
    Form_pg_namespace nspForm = NULL;
    Oid oid = 0;

    pg_debug("dboid=%d, nspname=%s, nspoid=%d, showInfo=%d\n", dboid, nspname, *nspoid, showInfo);

    tuple.t_data = NULL;
    if (!dboid)
        return 0;
    if (nspname && nspoid)
        *nspoid = 0;

    snprintf(nspfile, sizeof(nspfile), "%s/base/%d/%d", PGDataDir, dboid, NamespaceRelationId);
    if ((fd = open(nspfile, O_RDONLY | PG_BINARY, S_IRUSR | S_IWUSR)) == -1)
        pg_log(FATAL, "could not open file \"%s\" for reading: %m\n", nspfile);

    while (read(fd, buffer, BLCKSZ) == BLCKSZ)
    {
        PGPageCheckPage(nspfile, (PageHeader)buffer, blknum++);
        maxoff = PageGetMaxOffsetNumber(buffer);
        for (off = FirstOffsetNumber; off <= maxoff; off++)
        {
            itemid = PageGetItemId(buffer, off);
            tuple.t_data = (HeapTupleHeader) PageGetItem((Page)buffer, itemid);
            tuple.t_len = ItemIdGetLength(itemid);
            if (tuple.t_len <= 0 || !ItemIdIsUsed(itemid))
                continue;
            oid = HeapTupleGetOid(&tuple);
            nspForm = (Form_pg_namespace) GETSTRUCT(&tuple);
            if (!nspname && !nspoid)
            {
                printf("\tnamespace: %s\n", NameStr(nspForm->nspname));
                continue;
            }
            if (nspname && strcmp(nspname, NameStr(nspForm->nspname)) == 0)
            {
                if (nspoid)
                    *nspoid = oid;
                goto done;
            }
            if (nspoid && *nspoid == oid)
            {
                nspname = NameStr(nspForm->nspname);
                goto done;
            }
        }
    }

done:
    close(fd);
    if (showInfo)
    {
        if (nspname && (!nspoid || *nspoid))
        {
            printf("\t%-30s %d\n", "oid of the name space", oid);
            printf("\t%-30s %s\n", "name of the name space", NameStr(nspForm->nspname));
            printf("\t%-30s %d (%s)\n", "owner of the name space", nspForm->nspowner, PGAuthGetAuthInfo(nspForm->nspowner));
#ifdef CATALOG_VARLEN
            printf("\t%-30s %s\n", "acl of the name space", nspForm->nspacl);
#endif
        }
        else
            printf("invalid name or oid, can not show info.\n");
    }
    return nspname;
}

/*
 * PGIndexGetIndexRelid
 *     get indexrelid one by one for relation
 * Args:
 *     dboid[IN]      - database file node
 *     reloid[INT]    - relation oid
 *     lastidxid[INT] - last indexrelid
 * Ret:
 *     indexrelid
 */
static Oid
PGIndexGetIndexRelid(Oid dboid, Oid reloid, Oid lastidxid)
{
    char          idxfile[MAXPGPATH], buffer[BLCKSZ];
    int           fd, off, blknum=0;
    OffsetNumber maxoff = InvalidOffsetNumber;
    Oid           indexrelid=0;
    ItemId        itemid;
    HeapTupleData tuple;
    Form_pg_index idxForm;
    bool          begfind = false;

    if (!dboid || !reloid)
        return 0;
    if (!lastidxid)
        begfind = true;

    snprintf(idxfile, sizeof(idxfile), "%s/base/%d/%d", PGDataDir, dboid, IndexRelationId);
    if ((fd = open(idxfile, O_RDONLY | PG_BINARY, S_IRUSR | S_IWUSR)) == -1)
        pg_log(FATAL, "could not open file \"%s\" for reading: %m\n", idxfile);

    while (read(fd, buffer, BLCKSZ) == BLCKSZ)
    {
        PGPageCheckPage(idxfile, (PageHeader) buffer, blknum++);
        maxoff = PageGetMaxOffsetNumber(buffer);
        for (off = FirstOffsetNumber; off <= maxoff; off++)
        {
            itemid = PageGetItemId(buffer, off);
            tuple.t_data = (HeapTupleHeader) PageGetItem((Page) buffer, itemid);
            tuple.t_len = ItemIdGetLength(itemid);
            idxForm = (Form_pg_index) GETSTRUCT(&tuple);
            if (lastidxid == idxForm->indrelid)
            {
                begfind = true;
                continue;
            }
            if (begfind && reloid == idxForm->indrelid)
            {
                indexrelid = idxForm->indexrelid;
                goto done;
            }
        }
    }

done:
    close(fd);
    return indexrelid;
}

/*
 * PGIndexGetIndexInfo
 *     get index info
 * Args:
 *     dboid[IN]   - database file node
 *     reloid[INT] - relation oid
 *     idxoid[INT] - index oid
 */
static void
PGIndexGetIndexInfo(Oid dboid, Oid reloid, Oid idxoid, bool showUsage)
{
    char          idxfile[MAXPGPATH], buffer[BLCKSZ];
    int           fd, off, blknum=0;
    OffsetNumber maxoff = InvalidOffsetNumber;
    ItemId        itemid;
    HeapTupleData tuple;
    Form_pg_index idxForm;

    if (!dboid)
        return;

    snprintf(idxfile, sizeof(idxfile), "%s/base/%d/%d", PGDataDir, dboid, IndexRelationId);
    if ((fd = open(idxfile, O_RDONLY | PG_BINARY, S_IRUSR | S_IWUSR)) == -1)
        pg_log(FATAL, "could not open file \"%s\" for reading: %m\n", idxfile);

    while (read(fd, buffer, BLCKSZ) == BLCKSZ)
    {
        PGPageCheckPage(idxfile, (PageHeader) buffer, blknum++);
        maxoff = PageGetMaxOffsetNumber(buffer);
        for (off = FirstOffsetNumber; off <= maxoff; off++)
        {
            itemid = PageGetItemId(buffer, off);
            tuple.t_data = (HeapTupleHeader) PageGetItem((Page)buffer, itemid);
            tuple.t_len = ItemIdGetLength(itemid);
            if (tuple.t_len <= 0 || !ItemIdIsUsed(itemid))
                continue;
            idxForm = (Form_pg_index) GETSTRUCT(&tuple);
            if (reloid != idxForm->indrelid)
                continue;
            if (!idxoid)
            {
                printf("\tindex: %s\n", PGRelationGetRelName(dboid, idxForm->indexrelid));
                continue;
            }
            if (idxoid == idxForm->indexrelid)
            {
                struct stat statbuf;
                int res;
                Oid tblspcOid = 0;

                PGRelationGetSpcIdByRelId(dboid, 0, &idxoid, &tblspcOid);
                PGClassGetObjectPath(tblspcOid, dboid, idxoid, idxfile);
                if ((res = stat(idxfile, &statbuf)) < 0)
                    pg_log(WARNING, "could not stat file \"%s\": %m\n", idxfile);
                printf("\t%-50s %s\n", "Physical Address", idxfile);
                printf("\t%-50s %ld Bytes\n", "Physical size", res ? 0 : statbuf.st_size);
                printf("\t%-50s %s", "Creation time", res ? "unknown\n" : ctime(&statbuf.st_ctime));
                printf("\t%-50s %s", "Last modify time", res ? "unknown\n" : ctime(&statbuf.st_mtime));
                printf("\t%-50s %s\n", "Last access time", res ? "unknown\n" : ctime(&statbuf.st_atime));
                printf("\t%-50s %d\n", "OID of the index", idxForm->indexrelid);
                printf("\t%-50s %d\n", "OID of the relation it indexes", idxForm->indrelid);
                printf("\t%-50s %d\n", "number of columns in index", idxForm->indnatts);
                printf("\t%-50s %c\n", "is this a unique index?", idxForm->indisunique ? 'T' : 'F');
                printf("\t%-50s %c\n", "is this index for primary key?", idxForm->indisprimary ? 'T' : 'F');
                printf("\t%-50s %c\n", "is this index for exclusion constraint?", idxForm->indisexclusion ? 'T' : 'F');
                printf("\t%-50s %c\n", "is uniqueness enforced immediately?", idxForm->indimmediate ? 'T' : 'F');
                printf("\t%-50s %c\n", "is this the index last clustered by?", idxForm->indisclustered ? 'T' : 'F');
                printf("\t%-50s %c\n", "is this index valid for use by queries?", idxForm->indisvalid ? 'T' : 'F');
                printf("\t%-50s %c\n", "must we wait for xmin to be old?", idxForm->indcheckxmin ? 'T' : 'F');
                printf("\t%-50s %c\n", "is this index ready for inserts?", idxForm->indisready ? 'T' : 'F');
                printf("\t%-50s %c\n", "is this index alive at all?", idxForm->indislive ? 'T' : 'F');
                printf("\t%-50s %c\n", "is this index the identity for replication?", idxForm->indisreplident ? 'T' : 'F');
/*
                / variable-length fields start here, but we allow direct access to indkey /
                int2vector  indkey;         / column numbers of indexed cols, or 0 /

#ifdef CATALOG_VARLEN
                oidvector   indcollation;   / collation identifiers /
                oidvector   indclass;       / opclass identifiers /
                int2vector  indoption;      / per-column flags (AM-specific meanings) /
                pg_node_tree indexprs;      / expression trees for index attributes that
                                              are not simple column references; one for
                                              each zero entry in indkey[] /
                pg_node_tree indpred;       / expression tree for predicate, if a partial
                                              index; else NULL /
#endif
*/
                if (showUsage)
                {
                    PGRelationSpaceUsage(idxfile);
                }
                goto done;
            }
        }
    }

done:
    close(fd);
    return;
}

/*
 * PGPartitionGetParInfo
 *     get partition one by one for relation
 * Args:
 *     dboid[IN]   - database file node
 *     reloid[INT] - relation oid
 * Ret:
 *     oid of partition
 */
static Oid
PGPartitionGetParInfo(Oid dboid, Oid inhparent)
{
    char          inhfile[MAXPGPATH], buffer[BLCKSZ];
    int           fd, off, blknum=0;
    OffsetNumber maxoff = InvalidOffsetNumber;
    Oid           inhrelid=0;
    ItemId        itemid;
    HeapTupleData tuple;
    Form_pg_inherits inhForm;
    bool          begfind = false;
    static Oid    lastinhid = 0;

    if (!dboid || !inhparent)
        return 0;
    if (!lastinhid)
        begfind = true;

    snprintf(inhfile, sizeof(inhfile), "%s/base/%d/%d", PGDataDir, dboid, InheritsRelationId);
    if ((fd = open(inhfile, O_RDONLY | PG_BINARY, S_IRUSR | S_IWUSR)) == -1)
        pg_log(FATAL, "could not open file \"%s\" for reading: %m\n", inhfile);

    while (read(fd, buffer, BLCKSZ) == BLCKSZ)
    {
        PGPageCheckPage(inhfile, (PageHeader)buffer, blknum++);
        maxoff = PageGetMaxOffsetNumber(buffer);
        for (off = FirstOffsetNumber; off <= maxoff; off++)
        {
            itemid = PageGetItemId(buffer, off);
            tuple.t_data = (HeapTupleHeader) PageGetItem((Page)buffer, itemid);
            tuple.t_len = ItemIdGetLength(itemid);
            inhForm = (Form_pg_inherits) GETSTRUCT(&tuple);
            if (lastinhid == inhForm->inhrelid)
            {
                begfind = true;
                continue;
            }
            if (begfind && inhparent == inhForm->inhparent)
            {
                lastinhid = inhrelid = inhForm->inhrelid;
                goto done;
            }
        }
    }

done:
    close(fd);
    return inhrelid;
}

/*
 * PGRelationSpaceUsage
 *     get disk space usage of a relation
 * Args:
 *     file[IN] - file to read
 */
static void
PGRelationSpaceUsage(char *file)
{
    char  tmpath[MAXPGPATH];
    long size, totalPages=0;

    printf("\n");
    printf("\tType                  Pages\n");
    printf("\t---------------- ----------\n");

    snprintf(tmpath, sizeof(tmpath), "%s_fsm", file);
    size = GetFileSize(tmpath);
    printf("\tFreeSpaceMap     %10ld\n", size);
    totalPages += size;

    snprintf(tmpath, sizeof(tmpath), "%s_vm", file);
    size = GetFileSize(tmpath);
    printf("\tVisibilityMap    %10ld\n", size);
    totalPages += size;

    /*
    if (relForm->relhasindex)
    {
        Oid idxoid = 0;
        size = 0;
        while ((idxoid = PGIndexGetIndexRelid(dboid, tmpoid, idxoid)) != 0)
        {
            snprintf(tmpath, sizeof(tmpath), "%s_vm", file);
            size += GetFileSize(tmpath);
        }
    }
    printf("\tIndex            %10ld\n", size); totalPages += size;
*/
    size = GetFileSize(file);
    printf("\tData             %10ld\n", size);
    totalPages += size;

    printf("\t                 ----------\n");
    printf("\tTotal Pages      %10ld\n", totalPages);
}

/*
 * PGDatabaseCheckRelations
 *     check relations of database
 * Args:
 *     dboid[IN]    - database file node
 *     schoid[IN]   - name space oid
 *     usertab[IN]  - if only check usertab. TRUE: only user tab, FALSE: only catalog tab
 *     checkmap[IN] - if alse check mapfiles
 */
static void
PGDatabaseCheckRelations(Oid dboid, Oid schoid, bool usertab, bool checkmap)
{
    char          relfile[MAXPGPATH], buffer[BLCKSZ];
    int           fd, off, blknum=0;
    OffsetNumber maxoff = InvalidOffsetNumber;
    ItemId        itemid;
    HeapTupleData tuple;
    Form_pg_class relForm;
    Oid           tmpoid=0;
    char         *nspname=NULL;

    if (!dboid)
        return;

    snprintf(relfile, sizeof(relfile), "%s/base/%d/%d", PGDataDir, dboid, RelationRelationId);
    if ((fd = open(relfile, O_RDONLY | PG_BINARY, S_IRUSR | S_IWUSR)) == -1)
        pg_log(FATAL, "could not open file \"%s\" for reading: %m\n", relfile);

    while (read(fd, buffer, BLCKSZ) == BLCKSZ)
    {
        PGPageCheckPage(relfile, (PageHeader)buffer, blknum++);
        maxoff = PageGetMaxOffsetNumber(buffer);
        for (off = FirstOffsetNumber; off <= maxoff; off++)
        {
            itemid = PageGetItemId(buffer, off);
            tuple.t_data = (HeapTupleHeader) PageGetItem((Page)buffer, itemid);
            tuple.t_len = ItemIdGetLength(itemid);
            if (tuple.t_len <= 0 || !ItemIdIsUsed(itemid))
                continue;
            relForm = (Form_pg_class) GETSTRUCT(&tuple);
            tmpoid = HeapTupleGetOid(&tuple);
            nspname = PGNameSpaceGetSchemaInfo(dboid, NULL, &relForm->relnamespace, false);
#define IsSystemTable(oid, nspid, nspname) (\
    (oid) < FirstNormalObjectId || \
    (nspid) == PG_CATALOG_NAMESPACE || \
    (nspid) == PG_TOAST_NAMESPACE || \
    ((nspname) && strncmp((nspname), "pg_", 3) == 0))

            if ((usertab && IsSystemTable(tmpoid, relForm->relnamespace, nspname)) ||
                (!usertab && !IsSystemTable(tmpoid, relForm->relnamespace, nspname)))
                continue;
            printf("%s:\n", NameStr(relForm->relname));
            PGClassGetObjectPath(relForm->reltablespace, dboid, relForm->relfilenode, relfile);
            PGRelationCheckFile(relfile, InvalidBlockNumber, checkmap);
        }
    }

    close(fd);
    return;
}

/*
 * PGRelationGetRelName
 *     get relation name of relation by relation oid
 * Args:
 *     dboid[IN]   - database file node
 *     reloid[INT] - relation oid
 * Ret:
 *     relation name
 */
static char*
PGRelationGetRelName(Oid dboid, Oid reloid)
{
    char          relfile[MAXPGPATH], buffer[BLCKSZ], *relname=NULL;
    int           fd, off, blknum=0;
    OffsetNumber maxoff = InvalidOffsetNumber;
    ItemId        itemid;
    HeapTupleData tuple;
    Form_pg_class relForm;
    Oid           tmpoid = 0;

    if (!dboid || !reloid)
        return NULL;

    snprintf(relfile, sizeof(relfile), "%s/base/%d/%d", PGDataDir, dboid, RelationRelationId);
    if ((fd = open(relfile, O_RDONLY | PG_BINARY, S_IRUSR | S_IWUSR)) == -1)
        pg_log(FATAL, "could not open file \"%s\" for reading: %m\n", relfile);

    while (read(fd, buffer, BLCKSZ) == BLCKSZ)
    {
        PGPageCheckPage(relfile, (PageHeader)buffer, blknum++);
        maxoff = PageGetMaxOffsetNumber(buffer);
        for (off = FirstOffsetNumber; off <= maxoff; off++)
        {
            itemid = PageGetItemId(buffer, off);
            tuple.t_data = (HeapTupleHeader) PageGetItem((Page)buffer, itemid);
            tuple.t_len = ItemIdGetLength(itemid);
            if (tuple.t_len <= 0 || !ItemIdIsUsed(itemid))
                continue;
            relForm = (Form_pg_class) GETSTRUCT(&tuple);
            tmpoid = HeapTupleGetOid(&tuple);
            if (tmpoid > 0 && reloid == tmpoid)
            {
                relname = NameStr(relForm->relname);
                goto done;
            }
        }
    }

done:
    close(fd);
    return relname;
}

/*
 * PGRelationGetRelInfo
 *     read pg_class to get relation info
 * Args:
 *     dboid[IN]       - database file node
 *     schoid[IN]      - name space oid
 *     relname[IN]     - relation name
 *     showInfo[IN]    - if show detail info
 *     showUsage[IN]   - if show disk usage in detail info
 *     reloid[INT/OUT] - relation oid
 *     spcoid[out]     - table space oid
 * Ret:
 *     relation filenode
 */
static Oid
PGRelationGetRelInfo(Oid dboid, Oid schoid, char *relname, bool showInfo, bool showUsage, Oid *reloid, Oid *spcoid)
{
    char          relfile[MAXPGPATH], tmpfile[MAXPGPATH], buffer[BLCKSZ];
    int           fd, off, blknum=0;
    OffsetNumber maxoff = InvalidOffsetNumber;
    Oid           filenode=0;
    ItemId        itemid;
    HeapTupleData tuple;
    Form_pg_class relForm = NULL;
    Oid           tmpoid = 0;

    if (!relname && !reloid)
        filenode = -1;

    /* some special relation */
    if (!showInfo && (dboid == 0 || (relname && strncmp(relname, "pg_", 3) == 0)))
    {
        if (strcmp(relname, "pg_class") == 0)
            return RelationRelationId;
        else if (strcmp(relname, "pg_attribute") == 0)
            return AttributeRelationId;
        else if (strcmp(relname, "pg_attrdef") == 0)
            return AttrDefaultRelationId;
        else if (strcmp(relname, "pg_constraint") == 0)
            return ConstraintRelationId;
        else if (strcmp(relname, "pg_namespace") == 0)
            return NamespaceRelationId;
        else if (strcmp(relname, "pg_index") == 0)
            return IndexRelationId;
 
        /* only under global */
        if (strcmp(relname, "pg_authid") == 0)
            return AuthIdRelationId;
        else if (strcmp(relname, "pg_auth_members") == 0)
            return AuthMemRelationId;
        else if (strcmp(relname, "pg_tablespace") == 0)
            return TableSpaceRelationId;
        else if (strcmp(relname, "pg_database") == 0)
            return DatabaseRelationId;
    }

    snprintf(relfile, sizeof(relfile), "%s/base/%d/%d", PGDataDir, dboid, RelationRelationId);
    if ((fd = open(relfile, O_RDONLY | PG_BINARY, S_IRUSR | S_IWUSR)) == -1)
        pg_log(FATAL, "could not open file \"%s\" for reading: %m\n", relfile);

    while (read(fd, buffer, BLCKSZ) == BLCKSZ)
    {
        PGPageCheckPage(relfile, (PageHeader)buffer, blknum++);
        maxoff = PageGetMaxOffsetNumber(buffer);
        for (off = FirstOffsetNumber; off <= maxoff; off++)
        {
            TransactionId xmax;
            itemid = PageGetItemId(buffer, off);
            if (!ItemIdIsNormal(itemid) ||
                !ItemIdIsUsed(itemid) ||
                ItemIdIsDead(itemid))
                continue;
            tuple.t_data = (HeapTupleHeader) PageGetItem((Page)buffer, itemid);
            tuple.t_len = ItemIdGetLength(itemid);
            if (tuple.t_len <= 0 || !ItemIdIsUsed(itemid))
                continue;
            xmax = HeapTupleHeaderGetRawXmax(tuple.t_data);
            if (xmax < OldestXmin)
                continue;
            if (!HeapTupleIsValid(&tuple) ||
                HeapTupleHeaderXminFrozen(tuple.t_data))
                continue;
            if (!HeapTupleHeaderXminCommitted(tuple.t_data))
            {
                if (HeapTupleHeaderXminInvalid(tuple.t_data))
                    continue;
            }

            relForm = (Form_pg_class) GETSTRUCT(&tuple);
            if (schoid && schoid != relForm->relnamespace)
                continue;

            if (!relname && !reloid)
            {
                printf("\trelation: %s\n", NameStr(relForm->relname));
                continue;
            }

            tmpoid = HeapTupleGetOid(&tuple);
            if ((relname && strcmp(relname, NameStr(relForm->relname)) == 0) ||
                (tmpoid > 0 && reloid && *reloid == tmpoid))
            {
                filenode = relForm->relfilenode;
                if (reloid)
                    *reloid = tmpoid;
                if (spcoid)
                    *spcoid = relForm->reltablespace;
                goto done;
            }
        }
    }

done:
    close(fd);
    if (showInfo)
    {
        if (filenode)
        {
            struct stat statbuf;
            int res;
            assert(filenode == relForm->relfilenode);
            PGClassGetObjectPath(relForm->reltablespace, dboid, filenode, tmpfile);
            if ((res = stat(tmpfile, &statbuf)) < 0)
                pg_log(WARNING, "could not stat file \"%s\": %m\n", tmpfile);
            printf("\t%-50s %s\n", "Physical Address", tmpfile);
            printf("\t%-50s %ld Bytes\n", "Physical size", res ? 0 : statbuf.st_size);
            printf("\t%-50s %s", "Creation time", res ? "unknown\n" : ctime(&statbuf.st_ctime));
            printf("\t%-50s %s", "Last modify time", res ? "unknown\n" : ctime(&statbuf.st_mtime));
            printf("\t%-50s %s\n", "Last access time", res ? "unknown\n" : ctime(&statbuf.st_atime));
            printf("\t%-50s %s\n", "Class name", NameStr(relForm->relname));
            printf("\t%-50s %d (%s)\n", "OID of namespace", relForm->relnamespace, PGNameSpaceGetSchemaInfo(dboid, NULL, &relForm->relnamespace, false));
            printf("\t%-50s %d\n", "OID of table's implicit row type", relForm->reltype);
            printf("\t%-50s %d\n", "OID of underlying composite type", relForm->reloftype);
            printf("\t%-50s %d (%s)\n", "Class owner", relForm->relowner, PGAuthGetAuthInfo(relForm->relowner));
            if (relForm->relam)
                printf("\t%-50s %d\n", "Index access method", relForm->relam);
            else
                printf("\t%-50s %d (%s)\n", "Index access method", relForm->relam, "not an index");
            printf("\t%-50s %d\n", "Physical storage file", relForm->relfilenode);
            printf("\t%-50s %d (%s)\n", "Table space", relForm->reltablespace, relForm->reltablespace ? PGTableSpaceGetSpcInfo(relForm->reltablespace) : "pg_default");
            printf("\t%-50s %d\n", "Number of blocks (not up-to-date)", relForm->relpages);
            printf("\t%-50s %f\n", "Number of tuples (not up-to-date)", relForm->reltuples);
            printf("\t%-50s %d\n", "Number of all-visible blocks (not up-to-date)", relForm->relallvisible);
            printf("\t%-50s %d\n", "OID of toast table", relForm->reltoastrelid);
            printf("\t%-50s %c\n", "Has any indexes", relForm->relhasindex ? 'T' : 'F');
            printf("\t%-50s %c\n", "Is shared across databases", relForm->relisshared ? 'T' : 'F');
            printf("\t%-50s %c\n", "see RELPERSISTENCE_xxx constants below", relForm->relpersistence);
            printf("\t%-50s %c\n", "see RELKIND_xxx constants below", relForm->relkind);
            printf("\t%-50s %d\n", "Number of user attributes", relForm->relnatts);
            printf("\t%-50s %d\n", "Number of CHECK constraints for class", relForm->relchecks);
            printf("\t%-50s %c\n", "Generate OIDs for rows", relForm->relhasoids ? 'T' : 'F');
            printf("\t%-50s %c\n", "Has PRIMARY KEY index", relForm->relhaspkey ? 'T' : 'F');
            printf("\t%-50s %c\n", "Has any rules", relForm->relhasrules ? 'T' : 'F');
            printf("\t%-50s %c\n", "Has any TRIGGERs", relForm->relhastriggers ? 'T' : 'F');
            printf("\t%-50s %c\n", "Has derived classes", relForm->relhassubclass ? 'T' : 'F');
            printf("\t%-50s %c\n", "Is row security enabled", relForm->relrowsecurity ? 'T' : 'F');
            printf("\t%-50s %c\n", "Is row security forced for owners", relForm->relforcerowsecurity ? 'T' : 'F');
            printf("\t%-50s %c\n", "matview currently holds query results", relForm->relispopulated ? 'T' : 'F');
            printf("\t%-50s %c\n", "see REPLICA_IDENTITY_xxx constants", relForm->relreplident);
            printf("\t%-50s %d\n", "all Xids < this are frozen in this rel", relForm->relfrozenxid);
            printf("\t%-50s %d\n", "all multixacts in this rel are >= this", relForm->relminmxid);
            printf("\n");
            if (relForm->reltoastrelid)
                printf("\tToastTable: %s\n", PGRelationGetRelName(dboid, relForm->reltoastrelid));
            if (relForm->relhasindex)
            {
                Oid idxoid = 0;
                printf("\tIndexs:\n");
                while ((idxoid = PGIndexGetIndexRelid(dboid, tmpoid, idxoid)) != 0)
                    printf("\t\t%s\n", PGRelationGetRelName(dboid, idxoid));
            }
            if (Tflag)
                PGRelationSpaceUsage(tmpfile);
            printf("\n");
        }
    }
    return filenode;
}

/*
 * PGRelationCheckFile
 *     check files of relation
 * Args:
 *     file[IN]     - filepath of relation
 *     tbfnode[IN]  - filenode of relation. 0: the 'file' already include filenode
 *     blknum[IN]   - the blknum of file to check
 *     checkmap[IN] - if check map file of relation
 */
static void
PGRelationCheckFile(char *filepath, BlockNumber blknum, bool checkmap)
{
    if (PGRelationReadFile(filepath, blknum, PGPageCheckRows) && !quiet_mode)
        printf("check %s success\n", filepath);

    if (checkmap)
    {
        struct stat statbuf;
        char mapath[MAXPGPATH];

        snprintf(mapath, sizeof(mapath), "%s_vm", filepath);
        if ((stat(mapath, &statbuf)) == 0)
            if (PGRelationReadFile(mapath, blknum, PGPageCheckPage) && !quiet_mode)
                printf("check %s success\n", mapath);
 
        snprintf(mapath, sizeof(mapath), "%s_fsm", filepath);
        if ((stat(mapath, &statbuf)) == 0)
            if (PGRelationReadFile(mapath, blknum, PGPageCheckPage) && !quiet_mode)
                printf("check %s success\n", mapath);
    }
}

/*
 * PGRelationShowPage
 *     load pages of relation
 * Args:
 *     filepath[IN] - file path of relation
 *     blknum[IN]   - the block to show. 0: show all block
 *     checkmap[IN] - if also show map file
 */
static void
PGRelationShowPage(char *filepath, BlockNumber blknum, bool checkmap, int pgOpt)
{
    if (strstr(filepath, "_vm"))
    {
        PGRelationReadFile(filepath, blknum, PGPageOpt[pgOpt][1]);
        return;
    }
    if (strstr(filepath, "_fsm"))
    {
        PGRelationReadFile(filepath, blknum, PGPageOpt[pgOpt][2]);
        return;
    }

    PGRelationReadFile(filepath, blknum, PGPageOpt[pgOpt][0]);
    if (checkmap)
    {
        char mapath[MAXPGPATH];

        printf("visibility map:");
        snprintf(mapath, sizeof(mapath), "%s_vm", filepath);
        PGRelationReadFile(mapath, blknum, PGPageOpt[pgOpt][1]);

        printf("free space map:");
        snprintf(mapath, sizeof(mapath), "%s_fsm", filepath);
        PGRelationReadFile(mapath, blknum, PGPageOpt[pgOpt][2]);
    }
}

static int32
PGBlockPatchWrite(char *file, BlockNumber blknum, int32 pchoff, int32 oldval, int32 newval, int action)
{
    char   buffer[BLCKSZ];
    int    fd;
    off_t  seekpos;
    struct stat statbuf;
    int32  curval=0;

    if (stat(file, &statbuf) < 0)
        pg_log(FATAL, "could not get stat of file \"%s\" : %m\n", file);
    if (statbuf.st_size == 0 )
        pg_log(FATAL, "size of file \"%s\" is 0, can not do patch\n", file);
    if (statbuf.st_size < blknum * BLCKSZ)
        pg_log(FATAL, "block: %d is out of file \"%s\"\n", blknum, file);
    if ((fd = open(file, O_RDWR | PG_BINARY, S_IRUSR | S_IWUSR)) == -1)
        pg_log(FATAL, "could not open file \"%s\" for reading: %m\n", file);

    /* read block */
    seekpos = (off_t) BLCKSZ * blknum;
    if (lseek(fd, seekpos, SEEK_SET) != seekpos)
    {
        close(fd);
        pg_log(FATAL, "could not seek to block %u in file \"%s\"\n", blknum, file);
    }
    if (read(fd, buffer, BLCKSZ) != BLCKSZ)
    {
        close(fd);
        pg_log(FATAL, "could not read block %u in file \"%s\"\n", blknum, file);
    }

    curval = *(int32 *)(buffer+pchoff);
    if (action == PA_CREATE)
    {
        if (curval == newval)
        {
            close(fd);
            pg_log(FATAL, "the new value is same as block:%u offset:%d in file \"%s\"\n", blknum, pchoff, file);
        }
        *(int32 *)(buffer+pchoff) = newval;
    }
    else if (action == PA_UNDO)
    {
        if (curval != newval)
        {
            close(fd);
            pg_log(FATAL, "current value:%d is not patch.newval:%d, could not do unpatch on block %u of file \"%s\"\n",
                   curval, newval, blknum, file);
        }
        *(int32 *)(buffer+pchoff) = oldval;
    }
    else if (action == PA_REDO)
    {
        if (oldval && curval != oldval)
        {
            close(fd);
            pg_log(FATAL, "current value:%d is not patch.oldval:%d, could not do repatch on block %u of file \"%s\"\n",
                   curval, oldval, blknum, file);
        }
        *(int32 *)(buffer+pchoff) = newval;
    }
    else
        pg_log(FATAL, "unsupport patch action\n");

    /* write block */
    if (lseek(fd, seekpos, SEEK_SET) != seekpos)
    {
        close(fd);
        pg_log(FATAL, "could not seek to block %u in file \"%s\"\n", blknum, file);
    }
    if (write(fd, buffer, BLCKSZ) != BLCKSZ)
    {
        close(fd);
        pg_log(FATAL, "could not write file \"%s\": %m\n", file);
    }
    close(fd);

    return curval;
}

static void
PGBlockPatchCreate(char *file, BlockNumber blknum, int32 pchid, int32 pchoff, int32 pchval, char *pchname)
{
    char   pchfile[MAXPGPATH];
    int    fd;
    BlockPatch  patch;

    if (blknum == InvalidBlockNumber)
        pg_log(FATAL, "block number is must\n");
    patch.oldval = PGBlockPatchWrite(file, blknum, pchoff, 0, pchval, PA_CREATE);

    /* write log */
    snprintf(pchfile, sizeof(pchfile), "%s/%s", PGDataDir, DEFAULT_PATCH_FILENAME);
    if ((fd = open(pchfile, O_CREAT | O_WRONLY | PG_BINARY | O_APPEND, S_IRUSR | S_IWUSR)) == -1)
    {
        pg_log(FATAL, "could not open file \"%s\" for reading: %m\n", pchfile);
    }

    time(&patch.time);
    patch.state = PS_PATCHED;
    patch.blknum = blknum;
    patch.offset = pchoff;
    patch.newval = pchval;
    strcpy(patch.name, pchname);
    strcpy(patch.file, file);

    if (write(fd, (char *)&patch, sizeof(BlockPatch)) != sizeof(BlockPatch))
    {
        close(fd);
        pg_log(FATAL, "could not write file \"%s\": %m\n", pchfile);
    }
    close(fd);
    printf("Patch block patch success!\n");
    return;
}

static void
PGBlockPatchUpdate(int32 pchid, int action)
{
    char   pchfile[MAXPGPATH];
    int    i=0, j=0, pchfd, pchsize=sizeof(BlockPatch);
    off_t  seekpos;
    struct stat statbuf;
    BlockPatch  patch;

    snprintf(pchfile, sizeof(pchfile), "%s/%s", PGDataDir, DEFAULT_PATCH_FILENAME);
    if (stat(pchfile, &statbuf) < 0)
        pg_log(FATAL, "could not get stat of file \"%s\" : %m\n", pchfile);
    if (statbuf.st_size == 0 )
        pg_log(FATAL, "size of file \"%s\" is 0, can not do patch\n", pchfile);
    if (statbuf.st_size % pchsize != 0)
        pg_log(FATAL, "size of file \"%s\" is wrong, can not update patch\n", pchfile);

    /* read log */
    if ((pchfd = open(pchfile, O_RDWR | PG_BINARY, S_IRUSR | S_IWUSR)) == -1)
        pg_log(FATAL, "could not open file \"%s\" for reading: %m\n", pchfile);
    patch.state = PS_INIT;
    while (i < pchid && read(pchfd, (char *)&patch, pchsize) == pchsize)
    {
        if (patch.state != PS_DELETE)
            i++;
        j++;
    }
    if (patch.state == PS_INIT)
        pg_log(FATAL, "could not read file \"%s\": %m\n", pchfile);

    /* do patch */
    if (action == PA_UNDO)
    {
        if (patch.state != PS_PATCHED)
            pg_log(FATAL, "patch:%d state is not PATCHED, can not do unpatch\n", pchid);
        PGBlockPatchWrite(patch.file, patch.blknum, patch.offset, patch.oldval, patch.newval, action);
        patch.state = PS_UNPATCH;
    }
    else if (action == PA_REDO)
    {
        if (patch.state != PS_UNPATCH)
            pg_log(FATAL, "patch:%d state is not UNPATCH, can not do repatch\n", pchid);
        PGBlockPatchWrite(patch.file, patch.blknum, patch.offset, patch.oldval, patch.newval, action);
        patch.state = PS_PATCHED;
    }
    else if (action == PA_DELETE)
    {
        if (patch.state != PS_UNPATCH)
            pg_log(FATAL, "patch:%d state is not UNPATCH, can not do delete\n", pchid);
        patch.state = PS_DELETE;
    }
    else
        pg_log(FATAL, "unsupport patch action\n");

    /* write log */
    seekpos = (off_t) pchsize * (j-1);
    if (lseek(pchfd, seekpos, SEEK_SET) != seekpos)
    {
        close(pchfd);
        pg_log(FATAL, "could not seek to patch:%d in file \"%s\"\n", pchid, pchfile);
    }
    if (write(pchfd, (char *)&patch, pchsize) != pchsize)
        pg_log(FATAL, "could not write file \"%s\": %m\n", pchfile);
    close(pchfd);

    printf("%s block patch success!\n", (action == PA_UNDO) ? "Unpatch" : ((action == PA_REDO) ? "Repatch" : "Delete"));
    return;
}

static void
PGBlockPatchList(void)
{
    char   pchfile[MAXPGPATH];
    char   time_str[128];
    int    fd, i=0, pchsize=sizeof(BlockPatch);
    struct stat statbuf;
    BlockPatch  patch;

    snprintf(pchfile, sizeof(pchfile), "%s/%s", PGDataDir, DEFAULT_PATCH_FILENAME);
    if (stat(pchfile, &statbuf) < 0)
        pg_log(FATAL, "there is no block patch\n");
    if (statbuf.st_size % pchsize)
        pg_log(FATAL, "size of table file: %s is wrong\n", pchfile);

    if ((fd = open(pchfile, O_RDONLY | PG_BINARY, S_IRUSR | S_IWUSR)) == -1)
        pg_log(FATAL, "could not open file \"%s\" for reading: %m\n", pchfile);

    printf("   ID |  Time               | State   |   Blknum   |  Offset  |  OldValue  |  NewValue  | Name            | File\n");
    printf("------+---------------------+---------+------------+----------+------------+------------+-----------------+----------------------------\n");
    while (read(fd, (char *)&patch, pchsize) == pchsize)
    {
        if (patch.state == PS_DELETE)
            continue;

        strftime(time_str, sizeof(time_str), "%Y/%m/%d %H:%M:%S", localtime(&patch.time));
        printf("%5d | %s | ", ++i, time_str);
        switch(patch.state)
        {
            case PS_INIT:
                printf("%-7s", "INIT");
                break;
            case PS_UNPATCH:
                printf("%-7s", "UNPATCH");
                break;
            case PS_PATCHED:
                printf("%-7s", "PATCHED");
                break;
            case PS_DELETE:
                printf("%-7s", "DELETE");
                break;
            default:
                printf("%-7s", "UNKNOWN");
        }
        printf(" | %-10d | %-8d | 0x%x | 0x%x | %-15s | %s\n",
               patch.blknum, patch.offset, patch.oldval, patch.newval, patch.name, patch.file);
    }

    close(fd);
    return;
}

static void
PGCheckDispatch(char *filepath, BlockNumber blknum, int32 pchid, int32 pchoff, int32 pchval, char *pchname)
{
    struct stat statbuf;
    char  tmpath[MAXPGPATH], *tmpstr=NULL;
    char *dbname=NULL, *schname=NULL, *relname=NULL, *parname=NULL, *idxname=NULL;
    Oid   dboid=0, schoid=2200, tbfnode=0, reloid=0, paroid=0, idxoid=0, tblspcOid=0;

    if (filepath == NULL)
        return;

    /* object format1: absolute path */
    if ((stat(filepath, &statbuf)) == 0)
        goto dispatch;

    /* object format2: relative path */
    snprintf(tmpath, sizeof(tmpath), "%s/%s", PGDataDir, filepath);
    if ((stat(tmpath, &statbuf)) == 0)
    {
        filepath = tmpath;
        goto dispatch;
    }

    /* object format3: database[:[schema.]table[,partition]] */
    if (filepath)
        dbname = strtok_r(filepath, ":", &tmpstr);
    if (strchr(tmpstr, '.'))
        schname = strtok_r(tmpstr, ".", &tmpstr);
    if (strchr(tmpstr, ','))
    {
        relname = strtok_r(tmpstr, ",", &tmpstr);
        parname = tmpstr;
    }
    else if (strchr(tmpstr, '#'))
    {
        relname = strtok_r(tmpstr, "#", &tmpstr);
        idxname = tmpstr;
    }
    else
        relname = tmpstr;
    if (strlen(relname) == 0)
        relname = NULL;

    sprintf(CheckTodo+strlen(CheckTodo), "on %s:", dbname);
    if (schname)
        sprintf(CheckTodo+strlen(CheckTodo), "%s.", schname);
    if (relname)
        sprintf(CheckTodo+strlen(CheckTodo), "%s", relname);
    if (parname)
        sprintf(CheckTodo+strlen(CheckTodo), ",%s", parname);
    if (idxname)
        sprintf(CheckTodo+strlen(CheckTodo), "#%s", idxname);

    /* 1. get database info */
    dboid = PGDatabaseGetDBInfo(dbname, false);
    if (!dboid && strcmp(dbname, "global"))
    {
        PGDatabaseGetDBInfo(NULL, false);
        pg_log(FATAL, "There is no database named \"%s\"\n", dbname);
    }
    if (popt && (tflag || Tflag) && !schname && !relname)
    {
        /* print database info */
        PGDatabaseGetDBInfo(dbname, true);
        exit(1);
    }

    /* 2. get schema info */
    if (schname)
    {
        PGNameSpaceGetSchemaInfo(dboid, schname, &schoid, false);
        if (!schoid)
        {
            PGNameSpaceGetSchemaInfo(dboid, NULL, NULL, false);
            pg_log(FATAL, "There is no schema named \"%s\" under %s\n", schname, dbname);
        }
        if (popt && (tflag || Tflag) && !relname)
        {
            /* print schema info */
            PGNameSpaceGetSchemaInfo(dboid, schname, NULL, true);
            exit(1);
        }
    }

    /* 3. get table info */
    if (relname)
    {
        tbfnode = PGRelationGetRelIdAndSpcIdByName(dboid, schoid, relname, &reloid, &tblspcOid);
        if (!reloid)
        {
            PGRelationShowRelations(dboid, schoid);
            if (schname)
                pg_log(FATAL, "There is no table named \"%s\" under %s:%s, Maybe checkpoint is needed.\n", relname, dbname, schname);
            else
                pg_log(FATAL, "There is no table named \"%s\" under %s, Maybe checkpoint is needed.\n", relname, dbname);
        }
    }

    /* 4. get partition info */
    if (parname)
    {
        tbfnode = PGRelationGetRelIdAndSpcIdByName(dboid, schoid, parname, &paroid, &tblspcOid);
        if (!paroid)
        {
            while ((paroid = PGPartitionGetParInfo(dboid, reloid)) > 0)
                printf("\tpartition: %s\n", PGRelationGetRelName(dboid, paroid));
            if (schname)
                pg_log(FATAL, "There is no partition table named \"%s\" under %s:%s.%s\n", parname, dbname, schname, relname);
            else
                pg_log(FATAL, "There is no partition table named \"%s\" under %s:%s\n", parname, dbname, relname);
        }
        relname = parname;
    }

    /* 5. get index info */
    if (idxname)
    {
        tbfnode = PGRelationGetRelIdAndSpcIdByName(dboid, schoid, idxname, &idxoid, &tblspcOid);
        if (!idxoid)
        {
            PGIndexGetIndexInfo(dboid, reloid, 0, false);
            pg_log(FATAL, "can not find index: %s\n", idxname);
        }
        relname = idxname;
    }

    if (popt)
    {
        if (tflag || Tflag)
        {
            /* print table info */
            if (!dbname || !relname)
                pg_log(FATAL, "-pt must give database:[schema.]table[,partition] format.\n");

            /* hint: should by relname for partion and index obj */
            PGRelationShowRelInfoByRelName(dboid, schoid, relname, Tflag);
            if (!parname)
            {
                while ((paroid = PGPartitionGetParInfo(dboid, reloid)) > 0)
                {
                    printf("Partition table of %s:\n", relname);
                    PGRelationShowRelInfoByRelId(dboid, schoid, &paroid, Tflag);
                }
            }
            return;
        }
        if (iflag || Iflag)
        {
            /* print index info */
            if (!dbname || !relname || !idxname)
                pg_log(FATAL, "-pi must give database:[schema.]table#index format.\n");

            PGIndexGetIndexInfo(dboid, reloid, idxoid, Iflag);
            return;
        }
    }

    /* 6. make absolute filepath */
    PGClassGetObjectPath(tblspcOid, dboid, tbfnode, tmpath);
    filepath = tmpath;

dispatch:
    PGCheckPrintHeader(filepath, CheckTodo);

    if (copt)
    {
        /* check catalog or user table files */
        if (cflag || Cflag || dflag || Dflag)
        {
            if (dboid && !reloid)
                PGDatabaseCheckRelations(dboid, schoid, dflag || Dflag, Cflag || Dflag);
            else
                PGRelationCheckFile(filepath, blknum, Cflag || Dflag);
        }
    }
    if (popt)
    {
        /* print page or tuple info */
        if (pflag || Pflag)
            PGRelationShowPage(filepath, blknum, Pflag, PGOPT_PRINTPAGE);
        if (dflag || Dflag)
            PGRelationShowPage(filepath, blknum, Dflag, PGOPT_PRINTUPLE);
        if (kflag || Kflag)
            PGRelationShowIndexBTree(filepath, blknum, Kflag);
    }
    if (bopt)
    {
        /* block patch */
        if (pflag)
            PGRelationReadFile(filepath, blknum, PGPagePrintPageRawData);
        if (cflag)
            PGBlockPatchCreate(filepath, blknum, pchid, pchoff, pchval, pchname);
    }
}

static void
usage(const char *progname)
{
    printf("%s %s - check data file of PostgreSQL database(%s).\n\n", progname,PGCHECK_VERSION, PG_VERSION);
    printf("Usage: %s\t[-D DATADIR] [-c | -p | -b | -l]\n", progname);
    printf("\t\t{database:[schema.]table[,partition|#index] | filepath} [blocknum]\n");
    printf("\n"
    "  -D      - Data directory of database, default use PGDATA environment variable\n"
    "  -c      - Check Option\n"
    "      g   - global/pg_control\n"
    "      c   - catalog tables.             [database]\n"
    "      d   - user tables.                {database:[schema.]table[,partition|#index] | filepath} [blocknum]\n"
    "      D   - user tables including maps. {database:[schema.]table[,partition|#index] | filepath} [blocknum]\n"
    "  -p      - Print Option\n"
    "      v   - Install&Build info\n"
    "      s   - table space info\n"
    "      g   - pg_control(-cg)\n"
    "      m   - pg_filenode.map             [database]\n"
    "      r   - pg_internal.init            [database]\n"
    "      c   - database catalogs(-cc)      [database]\n"
    "      t   - table info.                 {database:[schema.]table[,partition|#index]}\n"
    "      T   - table info and utilization. {database:[schema.]table[,partition|#index]}\n"
    "      p   - data page.                  {database:[schema.]table[,partition|#index] | filepath} [blocknum]\n"
    "      P   - data page including maps.   {database:[schema.]table[,partition|#index] | filepath} [blocknum]\n"
    "      d   - data rows.                  {database:[schema.]table[,partition|#index] | filepath} [blocknum]\n"
    "      D   - data rows including maps.   {database:[schema.]table[,partition|#index] | filepath} [blocknum]\n"
    "      i   - index info.                 {database:[schema.]table#index}\n"
    "      I   - index info and utilization. {database:[schema.]table#index}\n"
    "      k   - index key info.             {database:[schema.]table#index | filepath} [blocknum]\n"
    "      K   - index key and page info.    {database:[schema.]table#index | filepath} [blocknum]\n"
    "  -b      - Block Option\n"
    "      l   - list all block patchs\n"
    "      p   - print a page block          {database:[schema.]table[,partition|#index] | filepath} {blocknum}\n"
    "      c   - create a block patch        {database:[schema.]table[,partition|#index] | filepath} {blocknum}\n"
    "                                        {-o offset -v value -n name}\n"
    "      u   - unpatch a block patch.      {patchid}\n"
    "      r   - repatch a block patch.      {patchid}\n"
    "      d   - delete  a block patch.      {patchid}\n"
    "  -l      - Log Option\n"
    "      x   - xlog files\n"
    "  -q      - Quiet mode, only print error messages\n"
    "  -y|n    - Answer YES/NO to all questions\n"
    "\n"
    "Report bugs to <leapking@126.com>.\n");
}

int
main(int argc, char *argv[])
{
    int    c;
    char  *obj_path = NULL;
    BlockNumber obj_blknum = InvalidBlockNumber;
    int32 pchid=0, pchoff=0, pchval=0;
    char *pchname=NULL;

    ProgramName = get_progname(argv[0]);
    if (find_my_exec(argv[0], MyExecPath) < 0)
    {
        fprintf(stderr, _("%s: could not find own program executable\n"), ProgramName);
        exit(1);
    }

    if (argc == 1)
        PGGlobalDataStructInfo();
    else
    {
        if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)
        {
            usage(ProgramName);
            exit(0);
        }
        if (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-V") == 0)
        {
            puts("pgcheck v1.0 for PostgreSQL " PG_VERSION);
            exit(0);
        }
    }

    for (c = 0; c < argc; c++)
        strcat(CheckArgs, argv[c]);

    memset(CheckTodo, 0, sizeof(CheckTodo));
    while ((c = getopt(argc, argv, "b:c:D:gl:np:qs:y")) != -1)
    {
        switch (c)
        {
            case 'g':
                prgm_debug = 1;
                break;
            case 'q':
                quiet_mode = 1;
                break;
            case 'y':
                all_yes = 1;
                break;
            case 'n':
                all_no = 1;
                break;
            /* specify the PGData dir */
            case 'D':
                PGDataDir = optarg;
                break;
            /* check data option */
            case 'c':
                copt = 1;
                switch(*optarg)
                {
                    /* check database catalog tables */
                    case 'c':
                        cflag = 1;
                        obj_path = pg_strdup(argv[optind++]);
                        strcpy(CheckTodo, "Check database catalogs");
                        break;
                    case 'C':
                        Cflag = 1;
                        obj_path = pg_strdup(argv[optind++]);
                        strcpy(CheckTodo, "Check database catalogs");
                        break;
                    /* check database user tables */
                    case 'd':
                        dflag = 1;
                        obj_path = pg_strdup(argv[optind++]);
                        strcpy(CheckTodo, "Check table data");
                        break;
                    case 'D':
                        Dflag = 1;
                        obj_path = pg_strdup(argv[optind++]);
                        strcpy(CheckTodo, "Check table data");
                        break;
                    /* check global control file */
                    case 'g':
                        gflag = 1;
                        break;
                    default:
                        printf("Unsuport option!\n");
                        exit(1);
                }
                break;
            /* print info option */
            case 'p':
                popt = 1;
                switch(*optarg)
                {
                    /* print database catalogs */
                    case 'c':
                        cflag = 1;
                        break;
                    /* print data row */
                    case 'd':
                        dflag = 1;
                        if (argc > optind)
                            obj_path = pg_strdup(argv[optind++]);
                        if (argc > optind)
                            obj_blknum = atoi(argv[optind++]);
                        strcpy(CheckTodo, "Print table data");
                        break;
                    case 'D':
                        Dflag = 1;
                        if (argc > optind)
                            obj_path = pg_strdup(argv[optind++]);
                        if (argc > optind)
                            obj_blknum = atoi(argv[optind++]);
                        strcpy(CheckTodo, "Print table data");
                        break;
                    /* print global control file */
                    case 'g':
                        gflag = 1;
                        break;
                    /* print index info */
                    case 'i':
                        iflag = 1;
                        if (argc > optind)
                            obj_path = pg_strdup(argv[optind++]);
                        strcpy(CheckTodo, "Print index info");
                        break;
                    case 'I':
                        Iflag = 1;
                        if (argc > optind)
                            obj_path = pg_strdup(argv[optind++]);
                        strcpy(CheckTodo, "Print index info");
                        break;
                    /* print index key info */
                    case 'k':
                        kflag = 1;
                        if (argc > optind)
                            obj_path = pg_strdup(argv[optind++]);
                        if (argc > optind)
                            obj_blknum = atoi(argv[optind++]);
                        strcpy(CheckTodo, "Print index key info");
                        break;
                    case 'K':
                        Kflag = 1;
                        if (argc > optind)
                            obj_path = pg_strdup(argv[optind++]);
                        if (argc > optind)
                            obj_blknum = atoi(argv[optind++]);
                        strcpy(CheckTodo, "Print index key info");
                        break;
                    /* print pg_filenode.map */
                    case 'm':
                        mflag = 1;
                        if (argc > optind)
                            obj_path = pg_strdup(argv[optind++]);
                        break;
                    /* print page info */
                    case 'p':
                        pflag = 1;
                        if (argc > optind)
                            obj_path = pg_strdup(argv[optind++]);
                        if (argc > optind)
                            obj_blknum = atoi(argv[optind++]);
                        strcpy(CheckTodo, "Print table page");
                        break;
                    case 'P':
                        Pflag = 1;
                        if (argc > optind)
                            obj_path = pg_strdup(argv[optind++]);
                        if (argc > optind)
                            obj_blknum = atoi(argv[optind++]);
                        strcpy(CheckTodo, "Print table page");
                        break;
                    /* print pg_internal.init */
                    case 'r':
                        rflag = 1;
                        if (argc > optind)
                            obj_path = pg_strdup(argv[optind++]);
                        break;
                    /* print table space info */
                    case 's':
                        sflag = 1;
                        break;
                    /* print table info */
                    case 't':
                        tflag = 1;
                        if (argc > optind)
                            obj_path = pg_strdup(argv[optind++]);
                        strcpy(CheckTodo, "Print table info");
                        break;
                    case 'T':
                        Tflag = 1;
                        if (argc > optind)
                            obj_path = pg_strdup(argv[optind++]);
                        strcpy(CheckTodo, "Print table info");
                        break;
                    /* print version info */
                    case 'v':
                        vflag = 1;
                        break;
                    default:
                        printf("Unsuport option!\n");
                        exit(1);
                }
                break;
            /* block patch option */
            case 'b':
                bopt = 1;
                switch(*optarg)
                {
                    /* list block patch */
                    case 'l':
                        strcpy(CheckTodo, "List block patches\n");
                        lflag = 1;
                        break;
                    /* create block patch */
                    case 'c':
                    {
                        int32 nset=0;
                        strcpy(CheckTodo, "Create block patch");
                        cflag = 1;
                        if (argc > optind)
                            obj_path = pg_strdup(argv[optind++]);
                        if (argc > optind)
                            obj_blknum = atoi(argv[optind++]);
                        while (argc > optind)
                        {
                            if (*argv[optind] == '-')
                            {
                                switch (*(argv[optind++]+1))
                                {
                                    case 'n':
                                        pchname = pg_strdup(argv[optind++]);
                                        nset++;
                                        break;
                                    case 'o':
                                        pchoff = atoi(argv[optind++]);
                                        nset++;
                                        break;
                                    case 'v':
                                        sscanf(argv[optind++], "0x%x", &pchval);
                                        nset++;
                                        break;
                                }
                            }
                        }
                        if (nset < 3)
                        {
                            printf("-o offset, -v value and -n name must be set!\n");
                            exit(1);
                        }
                        break;
                    }
                    /* print block */
                    case 'p':
                        strcpy(CheckTodo, "Print page block");
                        pflag = 1;
                        while (argc > optind)
                        {
                            if (*argv[optind] == '-' && *(argv[optind++]+1) == 'a')
                                ShowAll = true;
                            else
                            {
                                obj_path = pg_strdup(argv[optind++]);
                                if (argc > optind)
                                    obj_blknum = atoi(argv[optind++]);
                            }
                        }
                        break;
                    /* unpatch block patch */
                    case 'u':
                        strcpy(CheckTodo, "Unpatch block patch\n");
                        uflag = 1;
                        if (argc > optind)
                            pchid = atoi(argv[optind++]);
                        break;
                    /* repatch block patch */
                    case 'r':
                        strcpy(CheckTodo, "Repatch block patch\n");
                        rflag = 1;
                        if (argc > optind)
                            pchid = atoi(argv[optind++]);
                        break;
                    /* delete block patch */
                    case 'd':
                        strcpy(CheckTodo, "Delete block patch\n");
                        dflag = 1;
                        if (argc > optind)
                            pchid = atoi(argv[optind++]);
                        break;
                    default:
                        printf("Unsuport option!\n");
                        exit(1);
                }
                break;
            /* log option */
            case 'l':
                lopt = 1;
                switch(*optarg)
                {
                    /* list xlog files */
                    case 'x':
                        strcpy(CheckTodo, "List xlog files\n");
                        xflag = 1;
                        break;
                    default:
                        printf("Unsuport option!\n");
                        exit(1);
                }
                break;
            default:
                pg_log(FATAL, _("Try \"%s --help\" for more information.\n"), ProgramName);
        }
    }

    /* Check PGDATA */
    if (PGDataDir == NULL)
    {
        PGDataDir = getenv("PGDATA");
        if (PGDataDir == NULL)
        {
            fprintf(stderr, _("%s: no data directory specified\n"), ProgramName);
            fprintf(stderr, _("Try \"%s --help\" for more information.\n"), ProgramName);
            exit(1);
        }
    }

    /* Complain if any arguments remain */
    if (optind < argc)
    {
        fprintf(stderr, _("%s: too many command-line arguments (first is \"%s\")\n"), ProgramName, argv[optind]);
        fprintf(stderr, _("Try \"%s --help\" for more information.\n"), ProgramName);
        exit(1);
    }

    /* Get global control file */
    ControlFile = get_controlfile(PGDataDir, ProgramName);
    OldestXmin = ControlFile->checkPointCopy.oldestCommitTsXid;

    /* Dispatch */
    if ((popt || copt) && gflag)
        PGGlobalPrintCtrlFile(ControlFile);
    else if (popt && (vflag || sflag || mflag || rflag))
    {
        if (vflag)
            PGGlobalPrintInstallAndBuildInfo();
        else if (sflag)
            PGTableSpaceGetSpcInfo(0);
        else if (mflag || rflag)
        {
            Oid dboid =0;
            if (obj_path && (dboid = PGDatabaseGetDBInfo(obj_path, false)) == 0)
            {
                PGDatabaseGetDBInfo(NULL, false);
                pg_log(FATAL, "There is no database named %s\n", obj_path);
            }
            if (mflag)
                PGDatabasePrintMappingFile(dboid , 0);
            if (rflag)
                PGDatabasePrintRelCacheFile(dboid);
        }
    }
    else if (bopt && (lflag || uflag || rflag || dflag))
    {
        if (lflag)
            PGBlockPatchList();
        else if (uflag)
            PGBlockPatchUpdate(pchid, PA_UNDO);
        else if (rflag)
            PGBlockPatchUpdate(pchid, PA_REDO);
        else if (dflag)
            PGBlockPatchUpdate(pchid, PA_DELETE);
        else
            pg_log(FATAL, "unsupport patch action\n");
    }
    else if (lopt && (xflag))
    {
        if (xflag)
            PGGlobalGetXLogFiles(ControlFile);
    }
    else
    {
        if (obj_path == NULL)
            pg_log(FATAL, _("Try \"%s --help\" for more information.\n"), ProgramName);
        PGCheckDispatch(obj_path, obj_blknum, pchid, pchoff, pchval, pchname);
    }

    pfree(ControlFile);
    if (obj_path)
        pfree(obj_path);
    return 0;
}

