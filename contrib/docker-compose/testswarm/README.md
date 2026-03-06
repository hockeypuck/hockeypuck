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
You should wait *at least 60s* for the environment to fully stabilise before running the tests.

To perform the tests, run `make test`.

Currently implemented tests include:

* `totals` checks the total number of keys reported by the hockeypuck front end and postgres back ends of each instance.
    A successful test will return the same total for each.
* `pkslog` returns the most recent log output concerning each PKS peer connection.
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

3 PTree total:  1
3 DB total:     1

./tests/pkslog
0 latest PKS logs:
1 latest PKS logs:
2 latest PKS logs:
3 latest PKS logs:

echo "select * from userids order by identity asc;" | ./tests/dbq pg0
               rfingerprint               |                  uidstring             |        identity         | confidence 
------------------------------------------+----------------------------------------+-------------------------+------------
 e83e74f4c055132f36e449e51e57a33af5bb58be | Alice Lovelace <alice@openpgp.example> | alice@openpgp.example   |          0
(1 row)

echo "select * from userids order by identity asc;" | ./tests/dbq pg1
               rfingerprint               |                  uidstring                   |        identity         | confidence 
------------------------------------------+----------------------------------------------+-------------------------+------------
 0337e510a28ccfbfc887f0899c281b32a1e66a1d | Bob Babbage <bob@openpgp.example>            | bob@openpgp.example     |          0
 a9486d67cd987ab91f8e3c0bdd5e904400adff17 | Carol Oldstyle <carol@openpgp.example>       | carol@openpgp.example   |          0
 591fe256ba352619da2d05e49cb6950aa8f0eda2 | Ricarda S. Álvarez <ricarda@openpgp.example> | ricarda@openpgp.example |          0
(3 rows)
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
0 PTree total:  4
0 DB total:     4

1 PTree total:  4
1 DB total:     4

2 PTree total:  4
2 DB total:     4

3 PTree total:  4
3 DB total:     4

./tests/pkslog
0 latest PKS logs:
hkp0_1  | time="2025-06-22T16:40:46Z" level=info msg="temporarily adding hkp://hkp1:11371 to PKS target list"
1 latest PKS logs:
hkp1_1  | time="2025-06-22T16:40:46Z" level=info msg="temporarily adding hkp://hkp0:11371 to PKS target list"
2 latest PKS logs:
3 latest PKS logs:
hkp3_1  | time="2025-06-22T16:41:04Z" level=info msg="temporarily adding hkp://hkp0:11371 to PKS target list"

echo "select * from userids order by identity asc;" | ./tests/dbq pg0
               rfingerprint               |                  uidstring                   |        identity         | confidence 
------------------------------------------+----------------------------------------------+-------------------------+------------
 e83e74f4c055132f36e449e51e57a33af5bb58be | Alice Lovelace <alice@openpgp.example>       | alice@openpgp.example   |          0
 0337e510a28ccfbfc887f0899c281b32a1e66a1d | Bob Babbage <bob@openpgp.example>            | bob@openpgp.example     |          0
 a9486d67cd987ab91f8e3c0bdd5e904400adff17 | Carol Oldstyle <carol@openpgp.example>       | carol@openpgp.example   |          0
 591fe256ba352619da2d05e49cb6950aa8f0eda2 | Ricarda S. Álvarez <ricarda@openpgp.example> | ricarda@openpgp.example |          0
(4 rows)

echo "select * from userids order by identity asc;" | ./tests/dbq pg1
               rfingerprint               |                  uidstring                   |        identity         | confidence 
------------------------------------------+----------------------------------------------+-------------------------+------------
 e83e74f4c055132f36e449e51e57a33af5bb58be | Alice Lovelace <alice@openpgp.example>       | alice@openpgp.example   |          0
 0337e510a28ccfbfc887f0899c281b32a1e66a1d | Bob Babbage <bob@openpgp.example>            | bob@openpgp.example     |          0
 a9486d67cd987ab91f8e3c0bdd5e904400adff17 | Carol Oldstyle <carol@openpgp.example>       | carol@openpgp.example   |          0
 591fe256ba352619da2d05e49cb6950aa8f0eda2 | Ricarda S. Álvarez <ricarda@openpgp.example> | ricarda@openpgp.example |          0
(4 rows)
~~~

# Scenario 3

This is the same as scenario 2, except that the extra filter "testing" has been removed from the configuration of hkp0.
When entering scenario3 from scenario2, only hkp0 should be restarted.

hkp1 and hkp2 SHOULD remove hkp0 from their temporary PKS lists and revert to normal sync, but hkp3 should not.

## Expected test output after 2 minutes

~~~
./tests/totals
0 PTree total:  4
0 DB total:     4

1 PTree total:  4
1 DB total:     4

2 PTree total:  4
2 DB total:     4

3 PTree total:  4
3 DB total:     4

./tests/pkslog
0 latest PKS logs:
hkp0_1  | time="2025-06-22T16:46:58Z" level=info msg="removing any copies of hkp://hkp1:11371 from PKS target list"
1 latest PKS logs:
hkp1_1  | time="2025-06-22T16:46:58Z" level=info msg="removing any copies of hkp://hkp0:11371 from PKS target list"
2 latest PKS logs:
3 latest PKS logs:
hkp3_1  | time="2025-06-22T16:47:51Z" level=info msg="temporarily adding hkp://hkp0:11371 to PKS target list"

echo "select * from userids order by identity asc;" | ./tests/dbq pg0
               rfingerprint               |                  uidstring                   |        identity         | confidence 
------------------------------------------+----------------------------------------------+-------------------------+------------
 e83e74f4c055132f36e449e51e57a33af5bb58be | Alice Lovelace <alice@openpgp.example>       | alice@openpgp.example   |          0
 0337e510a28ccfbfc887f0899c281b32a1e66a1d | Bob Babbage <bob@openpgp.example>            | bob@openpgp.example     |          0
 a9486d67cd987ab91f8e3c0bdd5e904400adff17 | Carol Oldstyle <carol@openpgp.example>       | carol@openpgp.example   |          0
 591fe256ba352619da2d05e49cb6950aa8f0eda2 | Ricarda S. Álvarez <ricarda@openpgp.example> | ricarda@openpgp.example |          0
(4 rows)

echo "select * from userids order by identity asc;" | ./tests/dbq pg1
               rfingerprint               |                  uidstring                   |        identity         | confidence 
------------------------------------------+----------------------------------------------+-------------------------+------------
 e83e74f4c055132f36e449e51e57a33af5bb58be | Alice Lovelace <alice@openpgp.example>       | alice@openpgp.example   |          0
 0337e510a28ccfbfc887f0899c281b32a1e66a1d | Bob Babbage <bob@openpgp.example>            | bob@openpgp.example     |          0
 a9486d67cd987ab91f8e3c0bdd5e904400adff17 | Carol Oldstyle <carol@openpgp.example>       | carol@openpgp.example   |          0
 591fe256ba352619da2d05e49cb6950aa8f0eda2 | Ricarda S. Álvarez <ricarda@openpgp.example> | ricarda@openpgp.example |          0
(4 rows)
~~~

# Scenario 4

This is the same as scenario 3, except that hkp0 and hkp2 have `openpgp.example` configured as an enumerable domain.
On entering scenario 4, Alice's revocation key is submitted to hkp2.

## Expected test output after 2 minutes

~~~
./tests/totals
0 PTree total:  4
0 DB total:     4

1 PTree total:  4
1 DB total:     4

2 PTree total:  4
2 DB total:     4

3 PTree total:  4
3 DB total:     4

./tests/pkslog
0 latest PKS logs:
hkp0_1  | time="2025-06-22T16:46:58Z" level=info msg="removing any copies of hkp://hkp1:11371 from PKS target list"
1 latest PKS logs:
hkp1_1  | time="2025-06-22T16:46:58Z" level=info msg="removing any copies of hkp://hkp0:11371 from PKS target list"
2 latest PKS logs:
3 latest PKS logs:
hkp3_1  | time="2025-06-22T16:47:51Z" level=info msg="temporarily adding hkp://hkp0:11371 to PKS target list"

echo "select * from userids order by identity asc;" | ./tests/dbq pg0
               rfingerprint               |                  uidstring                   |        identity         | confidence 
------------------------------------------+----------------------------------------------+-------------------------+------------
 e83e74f4c055132f36e449e51e57a33af5bb58be | Alice Lovelace <alice@openpgp.example>       | alice@openpgp.example   |          0
 0337e510a28ccfbfc887f0899c281b32a1e66a1d | Bob Babbage <bob@openpgp.example>            | bob@openpgp.example     |          0
 a9486d67cd987ab91f8e3c0bdd5e904400adff17 | Carol Oldstyle <carol@openpgp.example>       | carol@openpgp.example   |          0
 591fe256ba352619da2d05e49cb6950aa8f0eda2 | Ricarda S. Álvarez <ricarda@openpgp.example> | ricarda@openpgp.example |          0
(4 rows)

echo "select * from userids order by identity asc;" | ./tests/dbq pg1
               rfingerprint               |                  uidstring                   |        identity         | confidence 
------------------------------------------+----------------------------------------------+-------------------------+------------
 0337e510a28ccfbfc887f0899c281b32a1e66a1d | Bob Babbage <bob@openpgp.example>            | bob@openpgp.example     |          0
 a9486d67cd987ab91f8e3c0bdd5e904400adff17 | Carol Oldstyle <carol@openpgp.example>       | carol@openpgp.example   |          0
 591fe256ba352619da2d05e49cb6950aa8f0eda2 | Ricarda S. Álvarez <ricarda@openpgp.example> | ricarda@openpgp.example |          0
(3 rows)
~~~

# Sample keys

Sample keys are loaded into the various instances as follows:

* alice: (4)ed25519legacy/EB85BB5FA33A75E15E944E63F231550C4F47E38E - hkp0
* bob: (4)rsa3072/D1A66E1A23B182C9980F788CFBFCC82A015E7330 - hkp1
* carol: (4)dsa3072/71FFDA004409E5DDB0C3E8F19BA789DC76D6849A - hkp2
* david: (6) - not currently used
* emma: (5) - not currently used
* john: (3)rsa1024/554FE2CC2D28B459 - hkp3 (deprecated key length, should fail)
* ricarda: (4)rsa3072/2ADE0F8AA0596BC94E50D2AD916253AB652EF195 - hkp3

In addition, alice and bob have revocation signatures, which are submitted in later test scenarios.
