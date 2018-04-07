# !/usr/bin/env python3
import json
import datetime as dt
from os import path

BASE_DATETIME = dt.datetime(year=1970, month=1, day=1)


class CacheRecord:
    def __init__(self, record_type: str, key: str, value: str,
                 expire_datetime: dt.datetime = dt.datetime.utcnow()):
        self.record_type = record_type
        self.key = key
        self.value = value
        self.expire_datetime = expire_datetime

    def with_ttl(self, seconds):
        self.expire_datetime = dt.datetime.utcnow() + \
                               dt.timedelta(seconds=seconds)
        return self

    @property
    def expired(self):
        return dt.datetime.utcnow() > self.expire_datetime

    def to_json(self) -> dict:
        return {"record_type": self.record_type,
                "key": self.key,
                "value": self.value,
                "expire_time": str(
                    (self.expire_datetime - BASE_DATETIME).total_seconds())}

    @staticmethod
    def from_json(obj: dict):
        try:
            expire_time = BASE_DATETIME + \
                          dt.timedelta(seconds=float(obj["expire_time"]))
            return CacheRecord(obj["record_type"], obj["key"], obj["value"],
                               expire_time)
        except KeyError as e:
            raise ValueError(e)


class Cache:
    def __init__(self):
        self.records = dict()

    def add(self, record: CacheRecord):
        if record.key not in self.records:
            self.records[record.key] = []
        self.records[record.key].append(record)

    def check_ttls(self):
        for key in self.records.keys():
            new_value = []
            for record in self.records[key]:
                if not record.expired:
                    new_value.append(record)
            self.records[key] = new_value

    def try_get(self, key: str) -> list:
        self.check_ttls()
        if key not in self.records:
            self.records[key] = []
        return self.records[key]

    def __contains__(self, item) -> bool:
        return item in self.records and self[item]

    def __getitem__(self, key) -> list:
        self.check_ttls()
        if key not in self.records:
            self.records[key] = []
        return self.records[key]

    def to_json(self) -> dict:
        self.check_ttls()
        json_obj = {}
        for key in self.records:
            json_obj[key] = list(
                [record.to_json() for record in self.records[key]])
        return json_obj

    @staticmethod
    def from_json(json_obj: dict):
        records = {}
        for key in json_obj:
            records[key] = list(
                [CacheRecord.from_json(obj) for obj in json_obj[key]])
        cache = Cache()
        cache.records = records
        return cache

    @staticmethod
    def try_load_from_file(filename):
        if path.exists(filename):
            with open(filename) as file:
                return Cache.from_json(json.load(file))
        else:
            return Cache()

    def save_to_file(self, filename):
        with open(filename, "w") as file:
            json.dump(self.to_json(), file,indent='    ')
