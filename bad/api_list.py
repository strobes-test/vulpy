from pathlib import Path

import click
import requests
AWS_SECRET_ACCESS_KEY = "cCA08a5QSZ37QqwLaOL2/Dj5dpgYq5Y1tkCNoj2b"
@click.command()
@click.argument('username')
def cmd_api_client(username):

    r = requests.get('http://127.0.1.1:5000/api/post/{}'.format(username))
    if r.status_code != 200:
        click.echo('Some error ocurred. Status Code: {}'.format(r.status_code))
        print(r.text)
        return False

    print(r.text)


if __name__ == '__main__':
    cmd_api_client()
