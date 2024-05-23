# OpenPGP Keyserver Website - Lite

[![GitHub license](https://img.shields.io/github/license/mattrude/pgpkeyserver-lite.svg)](https://github.com/mattrude/pgpkeyserver-lite/blob/master/LICENSE) [![GitHub tag](https://img.shields.io/github/tag/mattrude/pgpkeyserver-lite.svg)](https://github.com/mattrude/pgpkeyserver-lite/tags) [![GitHub commits since](https://img.shields.io/github/commits-since/mattrude/pgpkeyserver-lite/v2.0.svg)](https://github.com/mattrude/pgpkeyserver-lite/compare/v2.0...master) [![Open Issues](https://img.shields.io/github/issues-raw/mattrude/pgpkeyserver-lite.svg)](https://github.com/mattrude/pgpkeyserver-lite/issues) [![Maintenance](https://img.shields.io/maintenance/yes/2019.svg)](http://github.com/mattrude/pgpkeyserver-lite)

This repository holds the website for my OpenPGP Keyserver, but the lite version of it.

This is a static site using [bootstraps](http://getbootstrap.com/) v3.3.7.

## Using on your own site
This project is licensed under the [GNU General Public License, version 3](http://www.gnu.org/licenses/gpl-3.0.html), with this license, you are free to download, modify, and share this project, as long as you persurve those same rights for others.

The content of this repository may be dropped directly in your webserver&#39;s content directory, with minor modification to update the contact method.

### Installing
This is a simple "drop in site", as you only need to put the files in the correct spot for them to do there thing.

The simplist way of installing this site is via [git](http://git-scm.com/), you may install it with the below commands.

Assuming your webserver will server data in `/var/www/html`:

    git clone git@github.com:mattrude/pgpkeyserver-lite.git /var/www/html

If you do not wish to use git, you may just download it via the below command.

    mkdir -p /var/www/html && \
    curl -sL "https://github.com/mattrude/pgpkeyserver-lite/archive/master.tar.gz" |tar -xz --strip=1 -C /var/www/html/

### Configuring

After downloading and extracting the tarball, you need to modify the site to reflect the setup of your keyserver. There are two sections that need to be replaced. first you need to replace all instances of `###ENTERNAMEHERE###` with your own name. Next, replace the instance of `###ENTERPUBLICKEYHERE###` with your public key. Or you may of course modify the site in anyway you wish.

You may also see other examples of [configuration files in the wiki](https://github.com/mattrude/pgpkeyserver-lite/wiki).

This project is intented to be served via a real webserver ([nginx](http://nginx.org/en/), [apache](http://httpd.apache.org/), [lighttpd](http://www.lighttpd.net/)), if you wish to run sks without a proxy setup, you may use the [inline](https://github.com/mattrude/pgpkeyserver-lite/tree/inline) version of this project.

## Nginx Configuration

    #----------------------------------------------------------------------
    # OpenPGP Public SKS Key Server
    #----------------------------------------------------------------------

    server {
        listen 80;
        listen [::]:80;
        listen <set-your-IP>:11371;
        listen [set-your-IPv6-IP]:11371;
        server_name <set-your-hostname>;
        root /var/www/html;
        error_page 404 /404.html;

        location ~ (.git|LICENSE|readme.md) {
            deny all;
            return 404;
        }

        location /pks {
            proxy_pass         http://127.0.0.1:11371;
            proxy_pass_header  Server;
            add_header         Via "1.1 <set-your-hostname>:11371 (nginx)";
        }
    }

## License

                  GNU GENERAL PUBLIC LICENSE
                    Version 3, 29 June 2007

    OpenPGP Key Server Website "pgpkeyserver-lite"
    Copyright (C) 2012-2019 Matt Rude <matt@mattrude.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
