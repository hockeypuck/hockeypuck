# Hockeypuck Test Swarm

This is a test environment containing a large number of hockeypuck instances, intentionally configured to exhibit several pathological properties.
It is intented to test the robustness of an SKS network, and MUST NOT be used for any other purpose.
You will need a beefy Linux machine to run this, and the following packages installed:

* docker-compose
* jq
* make

# Usage

To set up a fresh environment, cd into this directory and run `make clean`.

To start the environment for a particular scenario `[N]`, run `make scenario[N]`.
The scenarios are intended to be started in numerical sequence.
You should wait *at least 60s* for each scenario to fully stabilise before running the tests.

To perform the tests, run `make test`.

Currently implemented tests include:

* `totals` checks the total number of keys reported by the hockeypuck front end and postgres back ends of each instance.
    A successful test will return the same total for each.
* `pkslog` returns the most recent log output concerning each PKS peer connection.
    Test success is scenario-dependent.
* `userids` returns the contents of the `userids` table in the postgres back end.
    Test success is scenario-dependent.

To see the full logs, run `docker-compose logs -f`.

# Scenario 1

The base scenario is as follows:

* hkp0 has an extra filter "testing" configured to simulate a breaking upgrade; it peers with hkp1 and hkp2 but due to the filter mismatch cannot reconcile with either.
* hkp1 peers with both hkp0 and hkp2; hkp2 should work correctly but hkp0 will not due to the filter mismatch.
* hkp2 peers with both hkp0 and hkp1; hkp1 should work correctly but hkp0 will not due to the filter mismatch.
* hkp3 attempts to peer with all the others, but this will not succeed because none of them peer back.

No PKS settings are enabled on any of the nodes.

The above configuration SHOULD NOT fully reconcile, although hkp1 and hkp2 SHOULD reconcile with each other.

## Expected test output after 2 minutes

~~~
./tests/totals
0 PTree total:  1
0 DB total:     1

1 PTree total:  2
1 DB total:     2

2 PTree total:  2
2 DB total:     2

3 PTree total:  2
3 DB total:     2

./tests/pkslog
0 latest PKS logs:
1 latest PKS logs:
2 latest PKS logs:
3 latest PKS logs:

./tests/userids
               rfingerprint               |                  uidstring             |        identity         | confidence 
------------------------------------------+----------------------------------------+-------------------------+------------
 e83e74f4c055132f36e449e51e57a33af5bb58be | Alice Lovelace <alice@openpgp.example> | alice@openpgp.example   |          0
(1 row)

               rfingerprint               |                  uidstring             |        identity         | confidence 
------------------------------------------+----------------------------------------+-------------------------+------------
 0337e510a28ccfbfc887f0899c281b32a1e66a1d | Bob Babbage <bob@openpgp.example>      | bob@openpgp.example     |          0
 a9486d67cd987ab91f8e3c0bdd5e904400adff17 | Carol Oldstyle <carol@openpgp.example> | carol@openpgp.example   |          0
(2 rows)

               rfingerprint               |                  uidstring             |        identity         | confidence 
------------------------------------------+----------------------------------------+-------------------------+------------
 0337e510a28ccfbfc887f0899c281b32a1e66a1d | Bob Babbage <bob@openpgp.example>      | bob@openpgp.example     |          0
 a9486d67cd987ab91f8e3c0bdd5e904400adff17 | Carol Oldstyle <carol@openpgp.example> | carol@openpgp.example   |          0
(2 rows)

                           rfingerprint                           |                  uidstring                   |        identity         | confidence 
------------------------------------------------------------------+----------------------------------------------+-------------------------+------------
 2ef62068543b5c6a6ebd587cbed4e45a22267fb26f435a5d87a2866aae9d9914 | David Deluxe <david@openpgp.example>         | david@openpgp.example   |          0
 591fe256ba352619da2d05e49cb6950aa8f0eda2                         | Ricarda S. Álvarez <ricarda@openpgp.example> | ricarda@openpgp.example |          0
(2 rows)
~~~

# Scenario 2

This is the same as scenario 1, except:

* hkp0's peer configuration for hkp1 (but not hkp2) has `pksFailover` set, so it should fall back to PKS sync with hkp1.
    It also has hkp3 in its explicit PKS peer list.
* hkp1 has `pksFailover` set on hkp0, so it should fall back to PKS sync with hkp0.    
    It also has hkp3 in its explicit PKS peer list.
* hkp2 is unchanged.
* hkp3 has no explicit PKS peer list, but it does have `pksFailover` set on hkp0.

The above configuration SHOULD fully reconcile.

## Expected test output after 2 minutes

~~~
./tests/totals
0 PTree total:  5
0 DB total:     5

1 PTree total:  5
1 DB total:     5

2 PTree total:  5
2 DB total:     5

3 PTree total:  5
3 DB total:     5

./tests/pkslog
0 latest PKS logs:
hkp0_1  | time="2025-06-22T16:40:46Z" level=info msg="temporarily adding hkp://hkp1:11371 to PKS target list"
1 latest PKS logs:
hkp1_1  | time="2025-06-22T16:40:46Z" level=info msg="temporarily adding hkp://hkp0:11371 to PKS target list"
2 latest PKS logs:
3 latest PKS logs:
hkp3_1  | time="2025-06-22T16:41:04Z" level=info msg="temporarily adding hkp://hkp0:11371 to PKS target list"

./tests/userids
                           rfingerprint                           |                  uidstring                   |        identity         | confidence 
------------------------------------------------------------------+----------------------------------------------+-------------------------+------------
 e83e74f4c055132f36e449e51e57a33af5bb58be                         | Alice Lovelace <alice@openpgp.example>       | alice@openpgp.example   |          0
 0337e510a28ccfbfc887f0899c281b32a1e66a1d                         | Bob Babbage <bob@openpgp.example>            | bob@openpgp.example     |          0
 a9486d67cd987ab91f8e3c0bdd5e904400adff17                         | Carol Oldstyle <carol@openpgp.example>       | carol@openpgp.example   |          0
 2ef62068543b5c6a6ebd587cbed4e45a22267fb26f435a5d87a2866aae9d9914 | David Deluxe <david@openpgp.example>         | david@openpgp.example   |          0
 591fe256ba352619da2d05e49cb6950aa8f0eda2                         | Ricarda S. Álvarez <ricarda@openpgp.example> | ricarda@openpgp.example |          0
(5 rows)

                           rfingerprint                           |                  uidstring                   |        identity         | confidence 
------------------------------------------------------------------+----------------------------------------------+-------------------------+------------
 e83e74f4c055132f36e449e51e57a33af5bb58be                         | Alice Lovelace <alice@openpgp.example>       | alice@openpgp.example   |          0
 0337e510a28ccfbfc887f0899c281b32a1e66a1d                         | Bob Babbage <bob@openpgp.example>            | bob@openpgp.example     |          0
 a9486d67cd987ab91f8e3c0bdd5e904400adff17                         | Carol Oldstyle <carol@openpgp.example>       | carol@openpgp.example   |          0
 2ef62068543b5c6a6ebd587cbed4e45a22267fb26f435a5d87a2866aae9d9914 | David Deluxe <david@openpgp.example>         | david@openpgp.example   |          0
 591fe256ba352619da2d05e49cb6950aa8f0eda2                         | Ricarda S. Álvarez <ricarda@openpgp.example> | ricarda@openpgp.example |          0
(5 rows)

                           rfingerprint                           |                  uidstring                   |        identity         | confidence 
------------------------------------------------------------------+----------------------------------------------+-------------------------+------------
 e83e74f4c055132f36e449e51e57a33af5bb58be                         | Alice Lovelace <alice@openpgp.example>       | alice@openpgp.example   |          0
 0337e510a28ccfbfc887f0899c281b32a1e66a1d                         | Bob Babbage <bob@openpgp.example>            | bob@openpgp.example     |          0
 a9486d67cd987ab91f8e3c0bdd5e904400adff17                         | Carol Oldstyle <carol@openpgp.example>       | carol@openpgp.example   |          0
 2ef62068543b5c6a6ebd587cbed4e45a22267fb26f435a5d87a2866aae9d9914 | David Deluxe <david@openpgp.example>         | david@openpgp.example   |          0
 591fe256ba352619da2d05e49cb6950aa8f0eda2                         | Ricarda S. Álvarez <ricarda@openpgp.example> | ricarda@openpgp.example |          0
(5 rows)

                           rfingerprint                           |                  uidstring                   |        identity         | confidence 
------------------------------------------------------------------+----------------------------------------------+-------------------------+------------
 e83e74f4c055132f36e449e51e57a33af5bb58be                         | Alice Lovelace <alice@openpgp.example>       | alice@openpgp.example   |          0
 0337e510a28ccfbfc887f0899c281b32a1e66a1d                         | Bob Babbage <bob@openpgp.example>            | bob@openpgp.example     |          0
 a9486d67cd987ab91f8e3c0bdd5e904400adff17                         | Carol Oldstyle <carol@openpgp.example>       | carol@openpgp.example   |          0
 2ef62068543b5c6a6ebd587cbed4e45a22267fb26f435a5d87a2866aae9d9914 | David Deluxe <david@openpgp.example>         | david@openpgp.example   |          0
 591fe256ba352619da2d05e49cb6950aa8f0eda2                         | Ricarda S. Álvarez <ricarda@openpgp.example> | ricarda@openpgp.example |          0
(5 rows)
~~~

# Scenario 3

This is the same as scenario 2, except that the extra filter "testing" has been removed from the configuration of hkp0.
When entering scenario3 from scenario2, only hkp0 should be restarted.

hkp1 and hkp2 SHOULD remove hkp0 from their temporary PKS lists and revert to normal sync, but hkp3 should not.

## Expected test output after 2 minutes

~~~
./tests/totals
0 PTree total:  5
0 DB total:     5

1 PTree total:  5
1 DB total:     5

2 PTree total:  5
2 DB total:     5

3 PTree total:  5
3 DB total:     5

./tests/pkslog
0 latest PKS logs:
hkp0_1  | time="2025-06-22T16:46:58Z" level=info msg="removing any copies of hkp://hkp1:11371 from PKS target list"
1 latest PKS logs:
hkp1_1  | time="2025-06-22T16:46:58Z" level=info msg="removing any copies of hkp://hkp0:11371 from PKS target list"
2 latest PKS logs:
3 latest PKS logs:
hkp3_1  | time="2025-06-22T16:47:51Z" level=info msg="temporarily adding hkp://hkp0:11371 to PKS target list"

./tests/userids
                           rfingerprint                           |                  uidstring                   |        identity         | confidence 
------------------------------------------------------------------+----------------------------------------------+-------------------------+------------
 e83e74f4c055132f36e449e51e57a33af5bb58be                         | Alice Lovelace <alice@openpgp.example>       | alice@openpgp.example   |          0
 0337e510a28ccfbfc887f0899c281b32a1e66a1d                         | Bob Babbage <bob@openpgp.example>            | bob@openpgp.example     |          0
 a9486d67cd987ab91f8e3c0bdd5e904400adff17                         | Carol Oldstyle <carol@openpgp.example>       | carol@openpgp.example   |          0
 2ef62068543b5c6a6ebd587cbed4e45a22267fb26f435a5d87a2866aae9d9914 | David Deluxe <david@openpgp.example>         | david@openpgp.example   |          0
 591fe256ba352619da2d05e49cb6950aa8f0eda2                         | Ricarda S. Álvarez <ricarda@openpgp.example> | ricarda@openpgp.example |          0
(5 rows)

                           rfingerprint                           |                  uidstring                   |        identity         | confidence 
------------------------------------------------------------------+----------------------------------------------+-------------------------+------------
 e83e74f4c055132f36e449e51e57a33af5bb58be                         | Alice Lovelace <alice@openpgp.example>       | alice@openpgp.example   |          0
 0337e510a28ccfbfc887f0899c281b32a1e66a1d                         | Bob Babbage <bob@openpgp.example>            | bob@openpgp.example     |          0
 a9486d67cd987ab91f8e3c0bdd5e904400adff17                         | Carol Oldstyle <carol@openpgp.example>       | carol@openpgp.example   |          0
 2ef62068543b5c6a6ebd587cbed4e45a22267fb26f435a5d87a2866aae9d9914 | David Deluxe <david@openpgp.example>         | david@openpgp.example   |          0
 591fe256ba352619da2d05e49cb6950aa8f0eda2                         | Ricarda S. Álvarez <ricarda@openpgp.example> | ricarda@openpgp.example |          0
(5 rows)

                           rfingerprint                           |                  uidstring                   |        identity         | confidence 
------------------------------------------------------------------+----------------------------------------------+-------------------------+------------
 e83e74f4c055132f36e449e51e57a33af5bb58be                         | Alice Lovelace <alice@openpgp.example>       | alice@openpgp.example   |          0
 0337e510a28ccfbfc887f0899c281b32a1e66a1d                         | Bob Babbage <bob@openpgp.example>            | bob@openpgp.example     |          0
 a9486d67cd987ab91f8e3c0bdd5e904400adff17                         | Carol Oldstyle <carol@openpgp.example>       | carol@openpgp.example   |          0
 2ef62068543b5c6a6ebd587cbed4e45a22267fb26f435a5d87a2866aae9d9914 | David Deluxe <david@openpgp.example>         | david@openpgp.example   |          0
 591fe256ba352619da2d05e49cb6950aa8f0eda2                         | Ricarda S. Álvarez <ricarda@openpgp.example> | ricarda@openpgp.example |          0
(5 rows)

                           rfingerprint                           |                  uidstring                   |        identity         | confidence 
------------------------------------------------------------------+----------------------------------------------+-------------------------+------------
 e83e74f4c055132f36e449e51e57a33af5bb58be                         | Alice Lovelace <alice@openpgp.example>       | alice@openpgp.example   |          0
 0337e510a28ccfbfc887f0899c281b32a1e66a1d                         | Bob Babbage <bob@openpgp.example>            | bob@openpgp.example     |          0
 a9486d67cd987ab91f8e3c0bdd5e904400adff17                         | Carol Oldstyle <carol@openpgp.example>       | carol@openpgp.example   |          0
 2ef62068543b5c6a6ebd587cbed4e45a22267fb26f435a5d87a2866aae9d9914 | David Deluxe <david@openpgp.example>         | david@openpgp.example   |          0
 591fe256ba352619da2d05e49cb6950aa8f0eda2                         | Ricarda S. Álvarez <ricarda@openpgp.example> | ricarda@openpgp.example |          0
(5 rows)
~~~

# Scenario 4

This is the same as scenario 3, except that hkp0 and hkp2 have `openpgp.example` configured as an enumerable domain.
On entering scenario 4, Alice's revocation key is submitted to hkp2.
(hkp2 is given a fresh database because hockeypuck-load does not currently support merging certificates)

hkp1 and hkp3 will remove Alice's userid due to the (hard) revocation on her primary key.
hkp0 and hkp2 will not remove her userid, because it matches an enumerable domain.

The output will be the same as above, but Alice will not be listed in the `userids` test on nodes hkp0 and hkp2.

## Expected test output after 2 minutes

~~~
./tests/totals
0 PTree total:  5
0 DB total:     5

1 PTree total:  5
1 DB total:     5

2 PTree total:  5
2 DB total:     5

3 PTree total:  5
3 DB total:     5

./tests/pkslog
0 latest PKS logs:
hkp0_1  | time="2025-06-22T16:46:58Z" level=info msg="removing any copies of hkp://hkp1:11371 from PKS target list"
1 latest PKS logs:
hkp1_1  | time="2025-06-22T16:46:58Z" level=info msg="removing any copies of hkp://hkp0:11371 from PKS target list"
2 latest PKS logs:
3 latest PKS logs:
hkp3_1  | time="2025-06-22T16:47:51Z" level=info msg="temporarily adding hkp://hkp0:11371 to PKS target list"

./tests/userids
                           rfingerprint                           |                  uidstring                   |        identity         | confidence 
------------------------------------------------------------------+----------------------------------------------+-------------------------+------------
 e83e74f4c055132f36e449e51e57a33af5bb58be                         | Alice Lovelace <alice@openpgp.example>       | alice@openpgp.example   |          0
 0337e510a28ccfbfc887f0899c281b32a1e66a1d                         | Bob Babbage <bob@openpgp.example>            | bob@openpgp.example     |          0
 a9486d67cd987ab91f8e3c0bdd5e904400adff17                         | Carol Oldstyle <carol@openpgp.example>       | carol@openpgp.example   |          0
 2ef62068543b5c6a6ebd587cbed4e45a22267fb26f435a5d87a2866aae9d9914 | David Deluxe <david@openpgp.example>         | david@openpgp.example   |          0
 591fe256ba352619da2d05e49cb6950aa8f0eda2                         | Ricarda S. Álvarez <ricarda@openpgp.example> | ricarda@openpgp.example |          0
(5 rows)

                           rfingerprint                           |                  uidstring                   |        identity         | confidence 
------------------------------------------------------------------+----------------------------------------------+-------------------------+------------
 0337e510a28ccfbfc887f0899c281b32a1e66a1d                         | Bob Babbage <bob@openpgp.example>            | bob@openpgp.example     |          0
 a9486d67cd987ab91f8e3c0bdd5e904400adff17                         | Carol Oldstyle <carol@openpgp.example>       | carol@openpgp.example   |          0
 2ef62068543b5c6a6ebd587cbed4e45a22267fb26f435a5d87a2866aae9d9914 | David Deluxe <david@openpgp.example>         | david@openpgp.example   |          0
 591fe256ba352619da2d05e49cb6950aa8f0eda2                         | Ricarda S. Álvarez <ricarda@openpgp.example> | ricarda@openpgp.example |          0
(5 rows)

                           rfingerprint                           |                  uidstring                   |        identity         | confidence 
------------------------------------------------------------------+----------------------------------------------+-------------------------+------------
 e83e74f4c055132f36e449e51e57a33af5bb58be                         | Alice Lovelace <alice@openpgp.example>       | alice@openpgp.example   |          0
 0337e510a28ccfbfc887f0899c281b32a1e66a1d                         | Bob Babbage <bob@openpgp.example>            | bob@openpgp.example     |          0
 a9486d67cd987ab91f8e3c0bdd5e904400adff17                         | Carol Oldstyle <carol@openpgp.example>       | carol@openpgp.example   |          0
 2ef62068543b5c6a6ebd587cbed4e45a22267fb26f435a5d87a2866aae9d9914 | David Deluxe <david@openpgp.example>         | david@openpgp.example   |          0
 591fe256ba352619da2d05e49cb6950aa8f0eda2                         | Ricarda S. Álvarez <ricarda@openpgp.example> | ricarda@openpgp.example |          0
(5 rows)

                           rfingerprint                           |                  uidstring                   |        identity         | confidence 
------------------------------------------------------------------+----------------------------------------------+-------------------------+------------
 0337e510a28ccfbfc887f0899c281b32a1e66a1d                         | Bob Babbage <bob@openpgp.example>            | bob@openpgp.example     |          0
 a9486d67cd987ab91f8e3c0bdd5e904400adff17                         | Carol Oldstyle <carol@openpgp.example>       | carol@openpgp.example   |          0
 2ef62068543b5c6a6ebd587cbed4e45a22267fb26f435a5d87a2866aae9d9914 | David Deluxe <david@openpgp.example>         | david@openpgp.example   |          0
 591fe256ba352619da2d05e49cb6950aa8f0eda2                         | Ricarda S. Álvarez <ricarda@openpgp.example> | ricarda@openpgp.example |          0
(5 rows)
~~~

# Scenario 5

This is the same as scenario 2, except that all nodes have `openpgp.example` configured as an enumerable domain.
In addition, all nodes are given fresh databases and restored from their original keydumps, apart from hkp0 which loads Alice's revoked key directly.

The above configuration SHOULD fully reconcile.
All nodes should recover Alice's redacted userid from hkp0 via SKS/PKS.

## Expected test output after 2 minutes

~~~
./tests/totals
0 PTree total:  5
0 DB total:     5

1 PTree total:  5
1 DB total:     5

2 PTree total:  5
2 DB total:     5

3 PTree total:  5
3 DB total:     5

./tests/pkslog
0 latest PKS logs:
hkp0_1  | time="2025-06-22T16:40:46Z" level=info msg="temporarily adding hkp://hkp1:11371 to PKS target list"
1 latest PKS logs:
hkp1_1  | time="2025-06-22T16:40:46Z" level=info msg="temporarily adding hkp://hkp0:11371 to PKS target list"
2 latest PKS logs:
3 latest PKS logs:
hkp3_1  | time="2025-06-22T16:41:04Z" level=info msg="temporarily adding hkp://hkp0:11371 to PKS target list"

./tests/userids
                           rfingerprint                           |                  uidstring                   |        identity         | confidence 
------------------------------------------------------------------+----------------------------------------------+-------------------------+------------
 e83e74f4c055132f36e449e51e57a33af5bb58be                         | Alice Lovelace <alice@openpgp.example>       | alice@openpgp.example   |          0
 0337e510a28ccfbfc887f0899c281b32a1e66a1d                         | Bob Babbage <bob@openpgp.example>            | bob@openpgp.example     |          0
 a9486d67cd987ab91f8e3c0bdd5e904400adff17                         | Carol Oldstyle <carol@openpgp.example>       | carol@openpgp.example   |          0
 2ef62068543b5c6a6ebd587cbed4e45a22267fb26f435a5d87a2866aae9d9914 | David Deluxe <david@openpgp.example>         | david@openpgp.example   |          0
 591fe256ba352619da2d05e49cb6950aa8f0eda2                         | Ricarda S. Álvarez <ricarda@openpgp.example> | ricarda@openpgp.example |          0
(5 rows)

                           rfingerprint                           |                  uidstring                   |        identity         | confidence 
------------------------------------------------------------------+----------------------------------------------+-------------------------+------------
 e83e74f4c055132f36e449e51e57a33af5bb58be                         | Alice Lovelace <alice@openpgp.example>       | alice@openpgp.example   |          0
 0337e510a28ccfbfc887f0899c281b32a1e66a1d                         | Bob Babbage <bob@openpgp.example>            | bob@openpgp.example     |          0
 a9486d67cd987ab91f8e3c0bdd5e904400adff17                         | Carol Oldstyle <carol@openpgp.example>       | carol@openpgp.example   |          0
 2ef62068543b5c6a6ebd587cbed4e45a22267fb26f435a5d87a2866aae9d9914 | David Deluxe <david@openpgp.example>         | david@openpgp.example   |          0
 591fe256ba352619da2d05e49cb6950aa8f0eda2                         | Ricarda S. Álvarez <ricarda@openpgp.example> | ricarda@openpgp.example |          0
(5 rows)

                           rfingerprint                           |                  uidstring                   |        identity         | confidence 
------------------------------------------------------------------+----------------------------------------------+-------------------------+------------
 e83e74f4c055132f36e449e51e57a33af5bb58be                         | Alice Lovelace <alice@openpgp.example>       | alice@openpgp.example   |          0
 0337e510a28ccfbfc887f0899c281b32a1e66a1d                         | Bob Babbage <bob@openpgp.example>            | bob@openpgp.example     |          0
 a9486d67cd987ab91f8e3c0bdd5e904400adff17                         | Carol Oldstyle <carol@openpgp.example>       | carol@openpgp.example   |          0
 2ef62068543b5c6a6ebd587cbed4e45a22267fb26f435a5d87a2866aae9d9914 | David Deluxe <david@openpgp.example>         | david@openpgp.example   |          0
 591fe256ba352619da2d05e49cb6950aa8f0eda2                         | Ricarda S. Álvarez <ricarda@openpgp.example> | ricarda@openpgp.example |          0
(5 rows)

                           rfingerprint                           |                  uidstring                   |        identity         | confidence 
------------------------------------------------------------------+----------------------------------------------+-------------------------+------------
 e83e74f4c055132f36e449e51e57a33af5bb58be                         | Alice Lovelace <alice@openpgp.example>       | alice@openpgp.example   |          0
 0337e510a28ccfbfc887f0899c281b32a1e66a1d                         | Bob Babbage <bob@openpgp.example>            | bob@openpgp.example     |          0
 a9486d67cd987ab91f8e3c0bdd5e904400adff17                         | Carol Oldstyle <carol@openpgp.example>       | carol@openpgp.example   |          0
 2ef62068543b5c6a6ebd587cbed4e45a22267fb26f435a5d87a2866aae9d9914 | David Deluxe <david@openpgp.example>         | david@openpgp.example   |          0
 591fe256ba352619da2d05e49cb6950aa8f0eda2                         | Ricarda S. Álvarez <ricarda@openpgp.example> | ricarda@openpgp.example |          0
(5 rows)
~~~

# HKP lookup tests

At any time, you can run HKP lookup tests by invoking `make testhkp`.
This will attempt to fetch Alice's and David's keys from all nodes, via all available HKP endpoints.

The precise output will depend on which scenario is currently active.
If invoked when scenario 2, 3 or 5 is stable, the lookup should return success for all tests on all nodes, with the exception of "get by-keyid David v2" which is expected to fail:

~~~
./tests/hkp
0 index Alice v1:               uid:Alice Lovelace <alice@openpgp.example>:1571135290::
0 get Alice v1:                 /dev/stdin: PGP public key block Secret-Key
0 index Alice v2: 				"keywords": "Alice Lovelace \u003calice@openpgp.example\u003e",
0 get by-identity Alice v2:     /dev/stdin: OpenPGP Public Key Version 4, Created Tue Jan 22 11:56:25 2019, EdDSA; User ID; Signature; OpenPGP Certificate
0 get by-vfingerprint Alice v2: /dev/stdin: OpenPGP Public Key Version 4, Created Tue Jan 22 11:56:25 2019, EdDSA; User ID; Signature; OpenPGP Certificate
0 get by-keyid Alice v2:        /dev/stdin: OpenPGP Public Key Version 4, Created Tue Jan 22 11:56:25 2019, EdDSA; User ID; Signature; OpenPGP Certificate

0 index David v1:               uid:David Deluxe <david@openpgp.example>:1744774099::
0 get David v1:                 /dev/stdin: PGP public key block
0 index David v2:               "keywords": "David Deluxe \u003cdavid@openpgp.example\u003e",
0 get by-identity David v2:     /dev/stdin: OpenPGP Public Key Version 6, Created Wed Apr 16 03:28:19 2025, Unknown Algorithm (0x1b); Signature; User ID; OpenPGP Certificate
0 get by-vfingerprint David v2: /dev/stdin: OpenPGP Public Key Version 6, Created Wed Apr 16 03:28:19 2025, Unknown Algorithm (0x1b); Signature; User ID; OpenPGP Certificate
0 get by-keyid David v2:        curl: (22) The requested URL returned error: 404
/dev/stdin: empty

0 prefixlog:                    2ade0f8a 4199d9ea 71ffda00 d1a66e1a eb85bb5f

1 index Alice v1:               uid:Alice Lovelace <alice@openpgp.example>:1571135290::
1 get Alice v1:                 /dev/stdin: PGP public key block Secret-Key
1 index Alice v2: 				"keywords": "Alice Lovelace \u003calice@openpgp.example\u003e",
1 get by-identity Alice v2:     /dev/stdin: OpenPGP Public Key Version 4, Created Tue Jan 22 11:56:25 2019, EdDSA; User ID; Signature; OpenPGP Certificate
1 get by-vfingerprint Alice v2: /dev/stdin: OpenPGP Public Key Version 4, Created Tue Jan 22 11:56:25 2019, EdDSA; User ID; Signature; OpenPGP Certificate
1 get by-keyid Alice v2:        /dev/stdin: OpenPGP Public Key Version 4, Created Tue Jan 22 11:56:25 2019, EdDSA; User ID; Signature; OpenPGP Certificate

1 index David v1:               uid:David Deluxe <david@openpgp.example>:1744774099::
1 get David v1:                 /dev/stdin: PGP public key block
1 index David v2:               "keywords": "David Deluxe \u003cdavid@openpgp.example\u003e",
1 get by-identity David v2:     /dev/stdin: OpenPGP Public Key Version 6, Created Wed Apr 16 03:28:19 2025, Unknown Algorithm (0x1b); Signature; User ID; OpenPGP Certificate
1 get by-vfingerprint David v2: /dev/stdin: OpenPGP Public Key Version 6, Created Wed Apr 16 03:28:19 2025, Unknown Algorithm (0x1b); Signature; User ID; OpenPGP Certificate
1 get by-keyid David v2:        curl: (22) The requested URL returned error: 404
/dev/stdin: empty

1 prefixlog:                    2ade0f8a 4199d9ea 71ffda00 d1a66e1a eb85bb5f

2 index Alice v1:               uid:Alice Lovelace <alice@openpgp.example>:1571135290::
2 get Alice v1:                 /dev/stdin: PGP public key block Secret-Key
2 index Alice v2: 				"keywords": "Alice Lovelace \u003calice@openpgp.example\u003e",
2 get by-identity Alice v2:     /dev/stdin: OpenPGP Public Key Version 4, Created Tue Jan 22 11:56:25 2019, EdDSA; User ID; Signature; OpenPGP Certificate
2 get by-vfingerprint Alice v2: /dev/stdin: OpenPGP Public Key Version 4, Created Tue Jan 22 11:56:25 2019, EdDSA; User ID; Signature; OpenPGP Certificate
2 get by-keyid Alice v2:        /dev/stdin: OpenPGP Public Key Version 4, Created Tue Jan 22 11:56:25 2019, EdDSA; User ID; Signature; OpenPGP Certificate

2 index David v1:               uid:David Deluxe <david@openpgp.example>:1744774099::
2 get David v1:                 /dev/stdin: PGP public key block
2 index David v2:               "keywords": "David Deluxe \u003cdavid@openpgp.example\u003e",
2 get by-identity David v2:     /dev/stdin: OpenPGP Public Key Version 6, Created Wed Apr 16 03:28:19 2025, Unknown Algorithm (0x1b); Signature; User ID; OpenPGP Certificate
2 get by-vfingerprint David v2: /dev/stdin: OpenPGP Public Key Version 6, Created Wed Apr 16 03:28:19 2025, Unknown Algorithm (0x1b); Signature; User ID; OpenPGP Certificate
2 get by-keyid David v2:        curl: (22) The requested URL returned error: 404
/dev/stdin: empty

2 prefixlog:                    2ade0f8a 4199d9ea 71ffda00 d1a66e1a eb85bb5f

3 index Alice v1:               uid:Alice Lovelace <alice@openpgp.example>:1571135290::
3 get Alice v1:                 /dev/stdin: PGP public key block Secret-Key
3 index Alice v2: 				"keywords": "Alice Lovelace \u003calice@openpgp.example\u003e",
3 get by-identity Alice v2:     /dev/stdin: OpenPGP Public Key Version 4, Created Tue Jan 22 11:56:25 2019, EdDSA; User ID; Signature; OpenPGP Certificate
3 get by-vfingerprint Alice v2: /dev/stdin: OpenPGP Public Key Version 4, Created Tue Jan 22 11:56:25 2019, EdDSA; User ID; Signature; OpenPGP Certificate
3 get by-keyid Alice v2:        /dev/stdin: OpenPGP Public Key Version 4, Created Tue Jan 22 11:56:25 2019, EdDSA; User ID; Signature; OpenPGP Certificate

3 index David v1:               uid:David Deluxe <david@openpgp.example>:1744774099::
3 get David v1:                 /dev/stdin: PGP public key block
3 index David v2:               "keywords": "David Deluxe \u003cdavid@openpgp.example\u003e",
3 get by-identity David v2:     /dev/stdin: OpenPGP Public Key Version 6, Created Wed Apr 16 03:28:19 2025, Unknown Algorithm (0x1b); Signature; User ID; OpenPGP Certificate
3 get by-vfingerprint David v2: /dev/stdin: OpenPGP Public Key Version 6, Created Wed Apr 16 03:28:19 2025, Unknown Algorithm (0x1b); Signature; User ID; OpenPGP Certificate
3 get by-keyid David v2:        curl: (22) The requested URL returned error: 404
/dev/stdin: empty

3 prefixlog:                    2ade0f8a 4199d9ea 71ffda00 d1a66e1a eb85bb5f
~~~

Note that the output of the `get` tests may differ slightly between operating system versions, depending on the implementation of the `file` utility.
The above output is correct for Debian 13.

# HKP submission tests

You can also run HKP submission tests while any scenario is active, by invoking `make testsubmission`.
Beware that this may invalidate any subsequent scenarios, unless you invoke `make clean` to start over.

The precise output will depend on which scenario is currently active.
If invoked when scenario 1 is stable, the following output is expected:

~~~
./tests/submission
0 submit Alice v1:          {"ignored":[{"version":4,"fingerprint":"eb85bb5fa33a75e15e944e63f231550c4f47e38e"}]}
0 submit David v2:            {"inserted":[{"version":6,"fingerprint":"4199d9eaa6682a78d5a534f62bf76222a54e4debc785dbe6a6c5b34586026fe2"}]}
0 get by-identity Alice v2: /dev/stdin: OpenPGP Public Key Version 4, Created Tue Jan 22 11:56:25 2019, EdDSA; User ID; Signature; OpenPGP Certificate
0 get by-identity David v2: /dev/stdin: OpenPGP Public Key Version 6, Created Wed Apr 16 03:28:19 2025, Unknown Algorithm (0x1b); Signature; User ID; OpenPGP Certificate
0 get David v1:               /dev/stdin: PGP public key block

1 submit Alice v1:          {"inserted":[{"version":4,"fingerprint":"eb85bb5fa33a75e15e944e63f231550c4f47e38e"}]}
1 submit David v2:            {"inserted":[{"version":6,"fingerprint":"4199d9eaa6682a78d5a534f62bf76222a54e4debc785dbe6a6c5b34586026fe2"}]}
1 get by-identity Alice v2: /dev/stdin: OpenPGP Public Key Version 4, Created Tue Jan 22 11:56:25 2019, EdDSA; User ID; Signature; OpenPGP Certificate
1 get by-identity David v2: /dev/stdin: OpenPGP Public Key Version 6, Created Wed Apr 16 03:28:19 2025, Unknown Algorithm (0x1b); Signature; User ID; OpenPGP Certificate
1 get David v1:               /dev/stdin: PGP public key block

2 submit Alice v1:          {"inserted":[{"version":4,"fingerprint":"eb85bb5fa33a75e15e944e63f231550c4f47e38e"}]}
2 submit David v2:            {"inserted":[{"version":6,"fingerprint":"4199d9eaa6682a78d5a534f62bf76222a54e4debc785dbe6a6c5b34586026fe2"}]}
2 get by-identity Alice v2: /dev/stdin: OpenPGP Public Key Version 4, Created Tue Jan 22 11:56:25 2019, EdDSA; User ID; Signature; OpenPGP Certificate
2 get by-identity David v2: /dev/stdin: OpenPGP Public Key Version 6, Created Wed Apr 16 03:28:19 2025, Unknown Algorithm (0x1b); Signature; User ID; OpenPGP Certificate
2 get David v1:               /dev/stdin: PGP public key block

3 submit Alice v1:          {"inserted":[{"version":4,"fingerprint":"eb85bb5fa33a75e15e944e63f231550c4f47e38e"}]}
3 submit David v2:            {"ignored":[{"version":6,"fingerprint":"4199d9eaa6682a78d5a534f62bf76222a54e4debc785dbe6a6c5b34586026fe2"}]}
3 get by-identity Alice v2: /dev/stdin: OpenPGP Public Key Version 4, Created Tue Jan 22 11:56:25 2019, EdDSA; User ID; Signature; OpenPGP Certificate
3 get by-identity David v2: /dev/stdin: OpenPGP Public Key Version 6, Created Wed Apr 16 03:28:19 2025, Unknown Algorithm (0x1b); Signature; User ID; OpenPGP Certificate
3 get David v1:               /dev/stdin: PGP public key block
~~~

All `submit` tests should return either `"inserted"` or `"ignored"`, depending on whether the key was already present on that node, with the exception of "get David v1" which is expected to fail.
If invoked when scenario 2 or 3 is stable, all `submit` tests should return `"ignored"`.
The `get` tests should always succeed, apart from "get David v1".

Note that the output of the `get` tests may differ slightly between operating system versions, depending on the implementation of the `file` utility.
The above output is correct for Debian 13.

FIXME: "get David v1" is failing in a non-standard way - it's returning an empty armor block instead of throwing an HTTP error such as 404, which would be more polite.

# Sample keys

Sample keys are loaded into the various instances as follows:

* alice:    (4)ed25519legacy/EB85BB5FA33A75E15E944E63F231550C4F47E38E - hkp0
* bob:      (4)rsa3072/D1A66E1A23B182C9980F788CFBFCC82A015E7330 - hkp1
* carol:    (4)dsa3072/71FFDA004409E5DDB0C3E8F19BA789DC76D6849A - hkp2
* david:    (6)ed25519/4199D9EAA6682A78D5A534F62BF76222A54E4DEBC785DBE6A6C5B34586026FE2 -hkp3
* emma:     (5) - not currently used
* john:     (3)rsa1024/554FE2CC2D28B459 - hkp3 (deprecated key length, should fail)
* ricarda:  (4)rsa3072/2ADE0F8AA0596BC94E50D2AD916253AB652EF195 - hkp3

In addition, alice and bob have revocation signatures, which are submitted in later test scenarios.
