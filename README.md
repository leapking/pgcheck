pgcheck - check data file of PostgreSQL database
================================================

Usage
-----
```
pgcheck - check data file of PostgreSQL database(9.6.6).
Usage: pgcheck  [-D DATADIR] [-c | -p | -b | -l]
                {database:[schema.]table[,partition|#index] | filepath} [blocknum]

  -D      - Data directory of database, default use PGDATA environment variable
  -c      - Check Option
      g   - global/pg_control
      c   - catalog tables.             [database]
      d   - user tables.                {database:[schema.]table[,partition|#index] | filepath} [blocknum]
      D   - user tables including maps. {database:[schema.]table[,partition|#index] | filepath} [blocknum]
  -p      - Print Option
      v   - Install&Build info
      s   - table space info
      g   - pg_control(-cg)
      m   - pg_filenode.map             [database]
      r   - pg_internal.init            [database]
      c   - database catalogs(-cc)      [database]
      t   - table info.                 {database:[schema.]table[,partition|#index]}
      T   - table info and utilization. {database:[schema.]table[,partition|#index]}
      p   - data page.                  {database:[schema.]table[,partition|#index] | filepath} [blocknum]
      P   - data page including maps.   {database:[schema.]table[,partition|#index] | filepath} [blocknum]
      d   - data rows.                  {database:[schema.]table[,partition|#index] | filepath} [blocknum]
      D   - data rows including maps.   {database:[schema.]table[,partition|#index] | filepath} [blocknum]
      i   - index info.                 {database:[schema.]table#index}
      I   - index info and utilization. {database:[schema.]table#index}
      k   - index key info.             {database:[schema.]table#index | filepath} [blocknum]
      K   - index key and page info.    {database:[schema.]table#index | filepath} [blocknum]
  -b      - Block Option
      s   - show a page block           {database:[schema.]table[,partition|#index] | filepath} {blocknum}
      p   - patch a block patch         {database:[schema.]table[,partition|#index] | filepath} {blocknum}
                                        {-o offset -v value -n name}
      l   - list all block patchs
      u   - unpatch a block patch.      {patchid}
      r   - repatch a block patch.      {patchid}
      d   - delete  a block patch.      {patchid}
  -l      - Log Option
      x   - xlog files
  -q      - Quiet mode, only print error messages
  -y|n    - Answer YES/NO to all questions
```
1. print info of database, schema, table, partition
   ![pgcheck -pt](https://leapking.github.io/images/016_pgcheck_01_pt.gif)
2. print page and tuple of relation
   ![pgcheck -pp](https://leapking.github.io/images/016_pgcheck_02_ppd.gif)
3. print index info and keys of index
   ![pgcheck -pi](https://leapking.github.io/images/016_pgcheck_03_pik.gif)
4. patch patches on raw page of relation
   ![pgcheck -bl](https://leapking.github.io/images/016_pgcheck_04_blpud.gif)

V1.0
-----
1. print info of xlog
2. print info of install and build
3. print info of pg_control
4. print info of pg_internal.init
5. print info of pg_filenode.map
6. print info of database, schema, table, partition or index
7. print, check and fix relation raw page or tuple
8. print, check and fix index keys

How to build
------------
Put current dir under src/bin and do ```make```

How to report bugs
------------------
有些功能做的有点糙，还有很多没有实现。欢迎学习和研究PG存储层的同学一起加入这个工具的开发。
Report bugs to **leapking@126.com**
