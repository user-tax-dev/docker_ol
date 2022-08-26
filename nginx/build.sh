#!/usr/bin/env bash

BUILDDIR="/tmp/nginx-quic"

DIR=$(dirname $(realpath "$0"))
cd $DIR
set -ex

# ---------------------------------------------------------------------------
# nginxquiccompile.sh - Compile nginx-quic with boringssl.

# By i81b4u.

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License at <http://www.gnu.org/licenses/> for
# more details.

# Usage: nginxquiccompile.sh [-h|--help]

# Revision history:
# 2020-10-01 Initial release.
# ---------------------------------------------------------------------------
PROGNAME=${0##*/}
VERSION="1.0.0"

mkdir -p $BUILDDIR

lastVer() {
  git ls-remote --refs --sort="version:refname" --tags $1 | cut -d/ -f3-|tail -n1
}

cd $BUILDDIR
if [ ! -d "lua-nginx-module" ]; then
#ver=$(lastVer https://github.com/openresty/lua-nginx-module.git)
#tgz=$ver.tar.gz
tgz=v0.10.14.tar.gz
wget -c https://github.com/openresty/lua-nginx-module/archive/$tgz
tar xvf $tgz
mv lua-nginx-module-* lua-nginx-module
sd -s "offsetof(ngx_http_headers_in_t, cookies)" "offsetof(ngx_http_headers_in_t, cookie)" lua-nginx-module/src/ngx_http_lua_headers_in.c
rm $tgz
fi

cd $BUILDDIR
if [ ! -e "luajit2" ]; then
git clone https://github.com/openresty/luajit2
cd luajit2
make
make install PREFIX=/usr/local/src/LuaJIT
#ln -s /usr/local/src/LuaJIT/lib/libluajit-5.1.so.2 /lib64/libluajit-5.1.so.2
fi

export LUAJIT_LIB=/usr/local/src/LuaJIT/lib
export LUAJIT_INC=/usr/local/src/LuaJIT/include/luajit-2.1
cd $BUILDDIR

if [ ! -d "ngx_brotli" ]; then
git clone --depth=1 --recursive https://github.com/google/ngx_brotli.git
fi

if [ ! -d "ngx_devel_kit" ]; then
git clone --depth=1 https://github.com/vision5/ngx_devel_kit.git
fi

if [ -x "$(command -v apt)" ]; then
$DIR/setup-ubuntu.sh
fi

clean_up() { # Perform pre-exit housekeeping
  return
}

error_exit() {
  echo -e "${PROGNAME}: ${1:-"Unknown Error"}" >&2
  clean_up
  exit 1
}

graceful_exit() {
  clean_up
  exit
}

signal_exit() { # Handle trapped signals
  case $1 in
    INT)
      error_exit "Program interrupted by user" ;;
    TERM)
      echo -e "\n$PROGNAME: Program terminated" >&2
      graceful_exit ;;
    *)
      error_exit "$PROGNAME: Terminating on unknown signal" ;;
  esac
}

usage() {
  echo -e "Usage: $PROGNAME [-h|--help]"
}

checkdeps_warn() {
  printf >&2 "$PROGNAME: $*\n"
}

checkdeps_iscmd() {
  command -v >&- "$@"
}

checkdeps() {
  local -i not_found
  for cmd; do
  checkdeps_iscmd "$cmd" || {
    checkdeps_warn $"$cmd not found"
    let not_found++
  }
  done
  (( not_found == 0 )) || return 1
}

help_message() {
  cat <<- _EOF_
  $PROGNAME ver. $VERSION
  Compile nginx-quic with boringssl.

  $(usage)

  Options:
  -h, --help  Display this help message and exit.

  NOTE: You must be the superuser to run this script.

  Modify variable BUILDDIR in this script to specify different build path.

_EOF_
  return
}

# Trap signals
trap "signal_exit TERM" TERM HUP
trap "signal_exit INT"  INT

# Check for root UID
if [[ $(id -u) != 0 ]]; then
  error_exit "You must be the superuser to run this script."
fi

# Parse command-line
while [[ -n $1 ]]; do
  case $1 in
    -h | --help)
      help_message; graceful_exit ;;
    -* | --*)
      usage
      error_exit "Unknown option $1" ;;
    *)
      echo "Argument $1 to process..." ;;
  esac
  shift
done

# Main logic

# Check dependencies (https://stackoverflow.com/questions/20815433/how-can-i-check-in-a-bash-script-if-some-software-is-installed-or-not)
echo "$PROGNAME: Checking dependencies..."
checkdeps git hg ninja wget patch sed make || error_exit "Install dependencies before using $PROGNAME"

# Create empty build environment
echo "$PROGNAME: Cleaning up previous build..."
if [ -d "$BUILDDIR" ]
then
  if [ -d "$BUILDDIR/nginx-quic" ]
  then
    rm -rf $BUILDDIR/nginx-quic || error_exit "Failed to delete directory $BUILDDIR/nginx-quic"
  fi
  if [ -d "$BUILDDIR/boringssl" ]
  then
    rm -rf $BUILDDIR/boringssl || error_exit "Failed to delete directory $BUILDDIR/boringssl"
  fi
else
  mkdir $BUILDDIR || error_exit "Failed to create directory $BUILDDIR."
fi

# Get nginx-quic and boringssl
echo "$PROGNAME: Cloning repositories..."
hg clone -b quic https://hg.nginx.org/nginx-quic $BUILDDIR/nginx-quic || error_exit "Failed to clone nginx-quic."
git clone https://boringssl.googlesource.com/boringssl $BUILDDIR/boringssl || error_exit "Failed to clone boringssl."

# Build boringssl
echo "$PROGNAME: Building boringssl..."
mkdir -p $BUILDDIR/boringssl/build || error_exit "Failed to create directory $BUILDDIR/boringssl/build."
cd $BUILDDIR/boringssl/build || error_exit "Failed to make $BUILDDIR/boringssl/build current directory."
cmake -GNinja .. || error_exit "Failed to cmake boringssl."
ninja || error_exit "Faied to compile boringssl."

# Modifications to boringssl to satisfy nginx-quic
echo "$PROGNAME: Modifying boringssl for nginx-quic..."
mkdir -p $BUILDDIR/boringssl/.openssl/lib || error_exit "Failed to create directory $BUILDDIR/boringssl/.openssl/lib."
ln -s $BUILDDIR/boringssl/include/ $BUILDDIR/boringssl/.openssl/include || error_exit "Failed to create symlink $BUILDDIR/boringssl/.openssl/include."
cp $BUILDDIR/boringssl/build/crypto/libcrypto.a $BUILDDIR/boringssl/.openssl/lib || error_exit "Failed to copy file $BUILDDIR/boringssl/build/crypto/libcrypto.a."
cp $BUILDDIR/boringssl/build/ssl/libssl.a $BUILDDIR/boringssl/.openssl/lib || error_exit "Failed to copy file $BUILDDIR/boringssl/build/ssl/libssl.a."

groupadd www-data || true
useradd www-data -g www-data -s /sbin/nologin -M || true
mkdir -p /var/log/nginx
chown www-data:www-data /var/log/nginx

# Configure-options like ubuntu
echo "$PROGNAME: Configure build options..."
if [ -d "$BUILDDIR/nginx-quic" ]
then
  cd $BUILDDIR/nginx-quic || error_exit "Failed to make $BUILDDIR/nginx-quic current directory."
  ./auto/configure \
    --user=www-data --group=www-data      \
    --prefix=/usr/local/nginx             \
    --sbin-path=/usr/sbin/nginx           \
    --conf-path=/etc/nginx/nginx.conf     \
    --pid-path=/var/run/nginx.pid         \
    --lock-path=/var/run/nginx.lock       \
    --error-log-path=/var/log/nginx/error.log \
    --http-log-path=/var/log/nginx/access.log \
    --with-cc-opt="-g0 -O3 -fstack-protector-strong -Wformat -Werror=format-security -fPIC -Wdate-time -march=native -pipe -flto -funsafe-math-optimizations --param=ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -I$BUILDDIR/boringssl/.openssl/include/" --with-ld-opt="-Wl,-Bsymbolic-functions -Wl,-z,relro -Wl,-z,now -fPIC -L$BUILDDIR/boringssl/.openssl/lib/" \
    --with-pcre-jit \
    --with-http_ssl_module \
    --with-http_stub_status_module --with-http_realip_module \
    --with-http_auth_request_module --with-http_v2_module \
    --with-http_v3_module --with-http_dav_module --with-http_slice_module \
    --with-threads --with-http_addition_module --with-http_geoip_module=dynamic \
    --with-http_gunzip_module --with-http_gzip_static_module --with-http_image_filter_module=dynamic --with-file-aio \
    --with-http_sub_module --with-http_xslt_module=dynamic --with-stream=dynamic --with-stream_ssl_module --with-mail=dynamic \
    --with-mail_ssl_module --with-openssl=$BUILDDIR/boringssl --with-openssl-opt='enable-tls1_3 enable-ec_nistp_64_gcc_128' \
    --add-module=$BUILDDIR/lua-nginx-module \
    --add-module=$BUILDDIR/ngx_devel_kit \
    --add-module=$BUILDDIR/ngx_brotli
else
        error_exit "Directory $BUILDDIR/nginx-quic does not exist."
fi

# Modify nginx http server string (nginx -> i81b4u)
echo "$PROGNAME: Modify nginx http server string..."
sed -i -e "s/static u_char ngx_http_server_string\[\] = \"Server: nginx\" CRLF\;/static u_char ngx_http_server_string\[\] = \"\" CRLF\;/g" $BUILDDIR/nginx-quic/src/http/ngx_http_header_filter_module.c || error_exit "Failed to modify http nginx server string."
# Modify nginx http/2 server string (https://scotthelme.co.uk/customising-server-header-over-http-2-in-nginx/)
sed -i -e "s/static const u_char nginx\[5\] \= \"\\\x84\\\xaa\\\x63\\\x55\\\xe7\"\;/static const u_char nginx\[0\] \= \"\"\;/g" $BUILDDIR/nginx-quic/src/http/v2/ngx_http_v2_filter_module.c || error_exit "Failed to modify http/2 nginx server string."

# Make and install
echo "$PROGNAME: Make and install nginx..."
if [ -d "$BUILDDIR/nginx-quic" ]
then
  touch $BUILDDIR/boringssl/.openssl/include/openssl/ssl.h || error_exit "Failed to touch $BUILDDIR/boringssl/.openssl/include/openssl/ssl.h."
        cd $BUILDDIR/nginx-quic || error_exit "Failed to make $BUILDDIR/nginx-quic current directory."
  make -j $(nproc) || error_exit "Error compiling nginx."
  make install || error_exit "Error installing nginx."
else
        error_exit "Directory $BUILDDIR/nginx-quic does not exist."
fi

grep -qF -- "www-data " /etc/security/limits.conf ||echo -e "\nwww-data soft nofile 252144\nwww-data hard nofile 262144\n" >> /etc/security/limits.conf
grep -qF -- "pam_limits.so" /etc/pam.d/common-session ||echo -e "\nsession required pam_limits.so\n" >> /etc/pam.d/common-session

rm /etc/ld.so.cache
ldconfig

systemctl enable nginx --now

echo "$PROGNAME: All done!"
graceful_exit
