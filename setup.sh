#!/bin/bash
# This script is meant to be a single button to push to get Bro set up and running on a Debian system.

###################################################
# SET THESE VARS TO CHANGE SCRIPT DEFAULT BEHAVIOR
# THEN DON'T TOUCH ANYTHING ELSE
#
LOG_FILE="setup.log";
PREFIX="/opt/bro";
WANT_GEOIP="Y";
WHICH_CMD="/usr/bin/which";
#
###################################################

DEPENDS="git cmake make gcc g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev libmagic-dev libgeoip-dev sendmail libcap2-bin libcurl3-dev wget gzip";

# Lazy command path location
SETCAP_CMD=$( ${WHICH_CMD} setcap );
D_CMD=$( ${WHICH_CMD} dpkg-query );

# use aptitude if available, apt-get if not
APT_CHECK=$(${D_CMD} -W --showformat='${Status}\n' aptitude | grep 'install ok installed');
if [[ ${APT_CHECK} = "install ok installed" ]]
then
	APT_CMD=$( which aptitude );
else
	APT_CMD=$( which apt-get );
fi

function log_it {
	echo "$(date +%s) : ${1}" >> ${LOG_FILE};
}

function depends {
	${APT_CMD} install -y ${DEPENDS};
	log_it "dependencies installed";
}

function geo_ip_stuff {
	${WGET_CMD} http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz;
	${GZIP_CMD} -d GeoLiteCity.dat.gz;
	mv GeoLiteCity.dat /usr/share/GeoIP/GeoIPCity.dat;
	${WGET_CMD} http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNum.dat.gz;
	${GZIP_CMD} -d GeoIPASNum.dat.gz;
	mv GeoIPASNum.dat /usr/share/GeoIP/GeoIPASNum.dat;
	export CFLAGS=-I/usr/local/include;
	export LDFLAGS=-L/usr/local/lib;
	log_it "geoIP stuff installed";
}

function bro_install {
	${GIT_CMD} clone --recursive https://github.com/bro/bro.git;
	if [ ! -d ${PREFEXI} ]
	then
		mkdir -p ${PREFIX};
	fi
	cd bro;
	./configure --prefix=${PREFIX};
	make && make install;
	log_it "bro installed at ${PREFIX}";
}

function make_nice {
	${SETCAP_CMD} cap_net_raw,cap_net_admin=eip ${PREFIX}/bin/bro;
	export PATH=${PATH}:${PREFIX}/bin;

	${GIT_CMD} clone git://github.com/mephux/bro.vim.git;
	if [ ! -d ~/.vim/syntax ]
	then
		mkdir -p ~/.vim/syntax;
	fi
	if [ ! -d ~/.vim/ftdetect ]
	then
		mkdir -p ~/.vim/ftdetect;
	fi
	cp -R bro.vim/syntax/* ~/.vim/syntax/;
	cp -R bro.vim/ftdetect/* ~/.vim/ftdetect/;
	rm -rf bro.vim;
	log_it "environment made nice";
}

depends;
WGET_CMD=$( ${WHICH_CMD} wget );
GZIP_CMD=$( ${WHICH_CMD} gzip );
GIT_CMD=$( ${WHICH_CMD} git );
if [[ ${WANT_GEOIP} = "Y" ]]
then
	geo_ip_stuff;
fi
bro_install;
make_nice;

echo "Setup finished. Check ${LOG_FILE} for details.";
