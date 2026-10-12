import zipfile

from customs_ml import misses


def test_members_closes_the_zip(tmp_path, monkeypatch):
    path = tmp_path / "a.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("a.txt", "x")
    opened = []

    class Recording(zipfile.ZipFile):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            opened.append(self)  # keeps it alive, so only an explicit close releases the file

    monkeypatch.setattr(misses.zipfile, "ZipFile", Recording)
    assert list(misses._members(str(path))) == [b"x"]
    assert len(opened) == 1 and opened[0].fp is None
