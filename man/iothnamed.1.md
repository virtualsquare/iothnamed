<!--
.\" Copyright (C) 2023 VirtualSquare. Project Leader: Renzo Davoli
.\"
.\" This is free documentation; you can redistribute it and/or
.\" modify it under the terms of the GNU General Public License,
.\" as published by the Free Software Foundation, either version 2
.\" of the License, or (at your option) any later version.
.\"
.\" The GNU General Public License's references to "object code"
.\" and "executables" are to be interpreted as the output of any
.\" document formatting or typesetting system, including
.\" intermediate and printed output.
.\"
.\" This manual is distributed in the hope that it will be useful,
.\" but WITHOUT ANY WARRANTY; without even the implied warranty of
.\" MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
.\" GNU General Public License for more details.
.\"
.\" You should have received a copy of the GNU General Public
.\" License along with this manual; if not, write to the Free
.\" Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
.\" MA 02110-1301 USA.
.\"
-->
# NAME

iothnamed(1) -- DNS server/forwarder/cache for the Internet of Threads

# SYNOPSIS

`iothnamed` [OPTIONS] *config\_file*

# DESCRIPTION

`iothnamed` is a DNS server/forwarder/cache for the Internet of Threads
supporting hash based IPv6 addresses and OTIP, i.e. one time IP.

The syntax of the *config_file* is described in iothnamed.conf(5).

# OPTIONS
  `-d`, `--daemon`
: run `iothnamed` as a daemon

  `-p`, `--pidfile`
: save the pid of the process in a file

# SEE ALSO
iothnamed.conf(5)

# AUTHOR
VirtualSquare. Project leader: Renzo Davoli.
