# Introduction

Create a redis database to correlate indicators extracted from malware samples.

# Installation

```
    pip install -r requirements.txt
```

You will also need processing

```
    sudo apt-get install processing
```

Prior to use the scripts in this directory, you may need to setup the following external projects:

* [MISP Redis Datastore](https://github.com/MISP/misp-redis-datastore/): you need to have access to the web service (locally or remotely) to be able to get the event IDs associated to the samples.
* The redis datastore also allows you to dump all the event information and CVE data (`get_digest.py` and `get_vulns.py`). Some of the example need you to import the CSV files with `import_digest_events.py` and `import_cve_events.py`
* [SSdeep Clustering](https://github.com/CIRCL/ssdc/tree/master/multiproc): if you want to generate statistics on ssdeep similarities between the samples.


Configure `correlator.conf` accordingly to your needs.

# Usage

Prior to generate the correlations we need to get all the event IDs associated to all the hashes (md5, sha1, sha256).
In order to do that, run

```
    ./correlator.py -d <directory containing the malwares>
```

After you run this script, you get a redis database containing keys like the following

```python
    hashes_md5 set(md5_1, md5_2, ...)
    hashes_sha1 set(sha_1, sha1_2, ...)
    hashes_sha256 set(sha256_1, sha256_2, ...)

    <sha256> hash('md5': <md5>, 'sha1': <sha1>, 'filename': <filename>, 'path': <path>, 'ssdeep': <ssdeep>)
```

The second step (optional) is to query the fast redis lookup web service to get all the event ID associated to the hashes:

```
    ./correlator.py -e
```

Creating the following keys:

``` python
    <md5>:eids set(eid1, eid2, ...)
    <sha1>:eids set(eid1, eid2, ...)
    <sha256>:eids set(eid1, eid2, ...)
```


And finally, the code doing the correlations with pefile:

```
    ./correlator.py -p
```

Creating the following keys:

``` python
    <sha256> hash('timestamp': <timestamp>, 'timestamp_iso': <timestamp_iso>, 'imphash': <imphash>,
                  'entrypoint': <entrypoint>, 'secnumber':<secnumber>, 'originalfilename':<originalfilename>,
                  'nb_tls': <nb_tls>, 'ep_section': <ep_section>, 'packed': <packed_value>)

    'timestamps' rankedset([timestamp, <frequency>, ...])
    'imphashs' rankedset([imphash, <frequency>, ...])
    'entrypoints' rankedset([entrypoint, <frequency>, ...])
    'secnumbers' rankedset([secnumber, <frequency>, ...])
    'originalfilenames' rankedset([originalfilename, <frequency>, ...])

    'timestamp:<timestamp>' set(sha256, ...)
    'imphash:<imphash>' set(sha256, ...)
    'entrypoint:<entrypoint>' set(sha256, ...)
    'secnumber:<secnumber>' set(sha256, ...)
    'originalfilename:<originalfilename>' set(sha256, ...)

    '<sha256>:secnames' set(secname, ...)
    '<sha256>:<secname>' hash('size': <size>, 'entropy': <entropy>)
```

# Long term use

All the keys and the entries mentioned earlier won't create duplicates if you reimport
the same malwares, except for the ranked sets.

To solve this problem, run the following to recompute all the ranked sets:

```
    ./rebuild_counters.py
```

# Helpers

`import_digest_events.py` creates following keys:

``` python
    'events' set(uuids)
    'eventuuid:<eid>' value(uuid)
    'eventids' set(event ids)

    'event:<uuid>' hash('eid': <eid>, 'info': <info>, 'date': <date>, 'timestamp': <timestamp> )
```
`import_cve_events.py` creates following keys:

``` python
    'event:<uuid>:cve' set(cves)
```

`only_subset.py` creates set in redis with event ids to care about

``` python
    'subset' set(uuids)
```


# Examples

* `CVE_events_clean.py`: Creates a MarkDown file listing which CVE is in which event
* `origfilenames_events_clean.py`: Creates a markdownfile listing the original filenames of the samples in each event
* `freq_by_indicators.py`: Dump csv files for each indicator extracted by pefile
* `originalfilenames_events.py`: csv listing all the original filenames of the samples by event
