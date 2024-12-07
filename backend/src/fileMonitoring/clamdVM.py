import os
from fabric import Connection


def test_file(username, ip, password, path):

    conn = Connection(
        host=ip,
        user=username,
        connect_kwargs={
            "password": password,
        },
    )
    file = (os.path.basename(path))
    print("Connected to system")

    conn.put(path, file)
    print("Sent the file")
    # conn.run('sudo systemctl start clamav-daemon.service')
    result = conn.run(f'clamdscan {file} --fdpass')
    # print(result.stdout)
    # print(result.stderr)

def modular_test_file(username, ip, password, path,command):

    conn = Connection(
        host=ip,
        user=username,
        connect_kwargs={
            "password": password,
        },
    )
    file = (os.path.basename(path))
    print("Connected to system")

    conn.put(path, file)
    print("Sent the file")
    result = conn.run(command)
    print(result.stdout)
    print(result.stderr)
# test_file(username, ip, password, "webshell.php")