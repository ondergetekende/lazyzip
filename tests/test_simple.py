import lazyzip
import zipfile

def test_simple_file(tmp_path):
    (tmp_path / 'hello.txt').write_text('hello')

    f = lazyzip.LazyZipFile(str(tmp_path))
    f.add_file('hello.txt')
    
    result = b''.join(f.as_iterable())
    zip_location = tmp_path / 'hello.zip'
    zip_location.write_bytes(result)

    zf = zipfile.ZipFile(zip_location)
    assert zf.namelist() == ['hello.txt']
    assert zf.open('hello.txt', 'r').read() == b'hello'