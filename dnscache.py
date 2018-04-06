# !/usr/bin/env python3
import json
import datetime as dt

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

    def to_json_obj(self) -> dict:
        return {"record_type": self.record_type,
                "key": self.key,
                "value": self.value,
                "expire_time": str(
                    (self.expire_datetime - BASE_DATETIME).total_seconds())}

    @staticmethod
    def from_json_obj(obj: dict):
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
        self.records[record.key] = record

    def check_ttls(self):
        keys_to_remove = []
        for key in self.records.keys():
            if self.records[key].expired:
                keys_to_remove.append(key)
        for key in keys_to_remove:
            self.records.pop(key)

    def try_get(self, key: str):
        self.check_ttls()
        if key in self.records:
            return self.records[key].value
        return None
