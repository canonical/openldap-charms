#
#
# utils/filedata.py

import base64
import grp
import hashlib
import json
import os
import pathlib
import pwd


class FileData:
    def __init__(self, encs=None):
        d = self._loads(encs) if encs != None else {}

        self.checksum = d.get("checksum", None)
        self.data = d.get("data", None)
        self.gid = d.get("gid", None)
        self.group = d.get("group", None)
        self.mode = d.get("mode", None)
        self.name = d.get("name", None)
        self.owner = d.get("owner", None)
        self.path = d.get("path", None)
        self.size = d.get("size", None)
        self.uid = d.get("uid", None)

    def __repr__(self):
        return self._dumps()

    def _dumps(self):
        if type(self.data) == bytes:
            dtype = "b"
            data = base64.b64encode(self.data).decode("utf-8")
        else:
            dtype = "t"
            data = self.data

        return json.dumps(
            {
                "checksum": self.checksum,
                "data": data,
                "dtype": dtype,
                "gid": self.gid,
                "group": self.group,
                "mode": self.mode,
                "name": self.name,
                "owner": self.owner,
                "path": self.path,
                "size": self.size,
                "uid": self.uid,
            }
        )

    def _loads(self, encs):
        d = json.loads(encs)
        if d.get("dtype", "t") == "b":
            d["data"] = base64.b64decode(d["data"].encode("utf-8"))
        return d

    def load(self, path, dtype="t", checksum=False):
        p = pathlib.Path(path)
        if not p.exists():
            raise Exception("file not found")

        self.set_data(p.read_text() if dtype == "t" else p.read_bytes(), checksum=checksum)
        self.path = str(p.resolve())
        self.name = p.name

        self.group = p.group()
        self.owner = p.owner()

        stat = p.stat()
        self.gid = stat.st_gid
        self.mode = stat.st_mode
        self.uid = stat.st_uid

    def save(self, path, mode=None, owner=None, group=None):
        try:
            owner = owner if owner != None else -1
            group = group if group != None else -1
            uid = owner if type(owner) == int else pwd.getpwnam(owner).pw_uid
            gid = group if type(group) == int else grp.getgrnam(group).gr_gid
        except:
            raise Exception("bad owner and/or group")

        p = pathlib.Path(path)
        p.touch()

        if (uid, gid) != (-1, -1):
            os.chown(path, uid, gid)

        if mode != None:
            p.chmod(mode)

        if type(self.data) == bytes:
            p.write_bytes(self.data)
        else:
            p.write_text(self.data)

    def set_data(self, data, checksum=False):
        bdata = data if type(data) == bytes else data.encode("utf-8")

        self.data = data
        self.size = len(bdata)
        if checksum:
            self.checksum = hashlib.sha224(bdata).hexdigest()