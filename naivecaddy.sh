#! /bin/bash
# [CTCGFW]Shell-Scripts
# Use it under GPLv3.
# --------------------------------------------------------
# NaiveCaddy Installer

# Color definition
DEFAULT_COLOR="\033[0m"
BLUE_COLOR="\033[36m"
GREEN_COLOR="\033[32m"
GREEN_BACK="\033[42;37m"
RED_COLOR="\033[31m"
RED_BACK="\033[41;37m"
YELLOW_COLOR="\033[33m"
YELLOW_BACK="\033[43;37m"

# File definition
CADDY_DIR="/usr/local/bin/naivecaddy"
CADDY_BIN="naivecaddy"
CADDY_CONF="Caddyfile"
SERVICE_FILE="/etc/systemd/system/naivecaddy.service"

function __error_msg() {
	echo -e "${RED_COLOR}[ERROR]${DEFAULT_COLOR} $1"
}

function __info_msg() {
	echo -e "${BLUE_COLOR}[INFO]${DEFAULT_COLOR} $1"
}

function __success_msg() {
	echo -e "${GREEN_COLOR}[SUCCESS]${DEFAULT_COLOR} $1"
}

function __warning_msg() {
	echo -e "${YELLOW_COLOR}[WARNING]${DEFAULT_COLOR} $1"
}

function base_check() {
	[ "${EUID}" -ne "0" ] && { __error_msg "You must run me with ROOT access."; exit 1; }

	[ "$(uname)" != "Linux" ] && { __error_msg "Your OS $(uname) is NOT SUPPORTED."; exit 1; }
	if [[ "aarch64 armv6l i686 x86_64" =~ (^|[[:space:]])"$(uname -m)"($|[[:space:]]) ]]; then
		SYSTEM_ARCH="$(uname -m)"
		SYSTEM_ARCH="${SYSTEM_ARCH/x86_64/amd64}"
	else
		__error_msg "Your architecture $(uname -m) is NOT SUPPORTED."
		exit 1
	fi

	[ -e "/etc/redhat-release" ] && SYSTEM_OS="RHEL"
	grep -q "Debian" "/etc/issue" && SYSTEM_OS="DEBIAN"
	grep -q "Ubuntu" "/etc/issue" && SYSTEM_OS="UBUNTU"
	[ -z "${SYSTEM_OS}" ] && { __error_msg "Your OS is not supported."; exit 1; }

	command -v "systemctl" > "/dev/null" || { __error_msg "Systemd is NOT FOUND."; exit 1; }
}

function check_status(){
	if [ -d "${CADDY_DIR}" ]; then
		INSTALL_STATUS="${GREEN_COLOR}Installed${DEFAULT_COLOR}"
		CADDY_PID="$(pidof "${CADDY_BIN}")"
		if [ -z "${CADDY_PID}" ]; then
			RUNNING_STATUS="${RED_COLOR}Not Running${DEFAULT_COLOR}"
			NAIVE_INFO="${RED_COLOR}Not Running${DEFAULT_COLOR}"
		else
			RUNNING_STATUS="${GREEN_COLOR}Running${DEFAULT_COLOR} | ${GREEN_COLOR}${CADDY_PID}${DEFAULT_COLOR}"
			NAIVE_DOMAIN="$(head -n1 "${CADDY_DIR}/${CADDY_CONF}" | sed "s/:443, //g")"
			NAIVE_USER="$(grep "basic_auth" "${CADDY_DIR}/${CADDY_CONF}" | awk -F ' ' '{print $2}')"
			NAIVE_PASS="$(grep "basic_auth" "${CADDY_DIR}/${CADDY_CONF}" | awk -F ' ' '{print $3}')"
			NAIVE_INFO="${GREEN_BACK}${NAIVE_USER}:${NAIVE_PASS}@${NAIVE_DOMAIN}:443${DEFAULT_COLOR}"
		fi
	else
		INSTALL_STATUS="${RED_COLOR}Not Installed${DEFAULT_COLOR}"
		RUNNING_STATUS="${RED_COLOR}Not Installed${DEFAULT_COLOR}"
		NAIVE_INFO="${RED_COLOR}Not Installed${DEFAULT_COLOR}"
	fi
}

function print_menu(){
	echo -e "NaiveCaddy Install Status: ${INSTALL_STATUS}
NaiveCaddy Running Status: ${RUNNING_STATUS}
----------------------------------------
	1. Install NaiveCaddy
	2. Remove NaiveCaddy

	3. Start/Stop NaiveCaddy
	4. Restart NaiveCaddy
----------------------------------------
NaiveInfo: ${NAIVE_INFO}
----------------------------------------"
	read -e -r -p "Action [1-4]: " DO_ACTION
	case "${DO_ACTION}" in
	"1")
		install_naivecaddy
		;;
	"2")
		remove_naivecaddy
		;;
	"3")
		start_stop_naivecaddy
		;;
	"4")
		restart_naivecaddy
		;;
	*)
		__error_msg "Number ${DO_ACTION} is NOT DEFINED."
		exit 1
		;;
	esac
}

function install_naivecaddy() {
	[ -d "${CADDY_DIR}" ] && {
		__info_msg "NaiveCaddy is installed already."
		read -e -r -p 'Do you want to reinstall? [y/N]: ' REINSTALL_NAIVECADDY
		case "${REINSTALL_NAIVECADDY}" in
		[yY][eE][sS]|[yY])
			__info_msg "Removing existing NaiveCaddy ..."
			remove_naivecaddy
			;;
		*)
			__error_msg "The action is canceled by user."
			exit 1
			;;
		esac
	}

	__info_msg "Installing dependencies ..."
	if [ "${SYSTEM_OS}" == "RHEL" ]; then
		yum update -y
		yum install -y epel-release
		yum install -y ca-certificates curl firewalld git lsof
		firewall-cmd --permanent --zone=public --add-port=22/tcp
		systemctl start firewalld
		firewall-cmd --reload
	else
		apt update -y
		apt install -y ca-certificates curl git lsof ufw
		ufw allow 22/tcp
		ufw enable <<-EOF
			y
		EOF
		ufw reload
	fi

	__info_msg "Checking port ..."
	for i in {80,443}
	do
		[ -n "$(lsof -i:"$i")" ] && {
			__error_msg "Port $i is already in use, see the following info:"
			lsof -i:"$i"
			read -e -r -p "Try to force kill the progress? [Y/n]: " PORT_CONFLICT_RESOLVE
			case "${PORT_CONFLICT_RESOLVE}" in
			[nN][oO]|[nN])
				__error_msg "The action is canceled by user."
				exit 1
				;;
			*)
				__info_msg "Trying to kill the progress ..."
				if lsof -i:"$i" | awk '{print $1}' | grep -v "COMMAND" | grep -q "apache"; then
					systemctl stop apache
					systemctl disable apache
					systemctl stop apache2
					systemctl disable apache2
				fi
				if lsof -i:"$i" | awk '{print $1}' | grep -v "COMMAND" | grep -q "caddy"; then
					systemctl stop caddy
					systemctl disable caddy
				fi
				if lsof -i:"$i" | awk '{print $1}' | grep -v "COMMAND" | grep -q "nginx"; then
					systemctl stop nginx
					systemctl disable nginx
				fi
				lsof -i:"$i" | awk '{print $2}' | grep -v "PID" | xargs kill -9
				__info_msg "Waiting for 5s ..."
				sleep 5s
				if lsof -i:"$i" > "/dev/null"; then
					__error_msg "Failed to kill the progress, please check it by yourself."
					exit 1
				else
					__success_msg "Progress now is killed."
				fi
				;;
			esac
		}
	done

	__info_msg "Please provide the following info: "
	read -e -r -p "Domain (e.g. example.com): " CONF_DOMAIN
	[ -z "${CONF_DOMAIN}" ] && { __error_msg "Domain cannot be empty."; exit 1; }
	read -e -r -p "E-mail (e.g. naive@example.com): " CONF_EMAIL
	[ -z "${CONF_EMAIL}" ] && { __error_msg "E-mail cannot be empty."; exit 1; }
	read -e -r -p "Username (e.g. user): " CONF_USER
	[ -z "${CONF_USER}" ] && { __error_msg "Username cannot be empty."; exit 1; }
	read -e -r -p "Password (e.g. pass): " CONF_PASS
	[ -z "${CONF_PASS}" ] && { __error_msg "Password cannot be empty."; exit 1; }

	INSTALL_TEMP_DIR="$(mktemp -p "/tmp" -d "naive.XXXXXX")"
	pushd "${INSTALL_TEMP_DIR}" || { __error_msg "Failed to enter tmp directory."; exit 1; }

	__info_msg "Checking go version ..."
	go version 2>"/dev/null" | grep -q "go1.15" || {
		__info_msg "Downloading Go 1.15 ..."

		GO_LATEST_VER="$(curl -sL --retry "5" --retry-delay "3" "https://github.com/golang/go/tags" | grep -Eo "go1\.16\.[0-9]+" | sed -n "1p" || echo "go1.16.12")"
		curl --retry "5" --retry-delay "3" --location "https://golang.org/dl/${GO_LATEST_VER}.linux-${SYSTEM_ARCH}.tar.gz" --output "golang.${GO_LATEST_VER}.tar.gz"
		tar -zxf "golang.${GO_LATEST_VER}.tar.gz"
		rm -f "golang.${GO_LATEST_VER}.tar.gz"
		[ ! -f "./go/bin/go" ] && { __error_msg "Failed to download go binary."; popd; rm -rf "${INSTALL_TEMP_DIR}"; exit 1; }

		export PATH="$PWD/go/bin:$PATH"
		export GOROOT="$PWD/go"
		export GOTOOLDIR="$PWD/go/pkg/tool/linux_$SYSTEM_ARCH"
	}

	export GOBIN="$PWD/gopath/bin"
	export GOCACHE="$PWD/go-cache"
	export GOPATH="$PWD/gopath"
	export GOMODCACHE="$GOPATH/pkg/mod"

	__info_msg "Fetching Caddy builder ..."
	go get -u "github.com/caddyserver/xcaddy/cmd/xcaddy"
	__info_msg "Building NaiveCaddy (this may take a few minutes to be completed) ..."
	"${GOBIN}/xcaddy" build --with "github.com/caddyserver/forwardproxy@caddy2=github.com/klzgrad/forwardproxy@naive"

	if [ -n "$(./caddy version)" ]; then
		__success_msg "NaiveCaddy version: $(./caddy version)"
	else
		__error_msg "Failed to build NaiveCaddy."
		popd
		rm -rf "${INSTALL_TEMP_DIR}"
		exit 1
	fi

	mkdir -p "${CADDY_DIR}"
	mv "./caddy" "${CADDY_DIR}/${CADDY_BIN}"
	setcap cap_net_bind_service=+ep "${CADDY_DIR}/${CADDY_BIN}"

	popd
	rm -rf "${INSTALL_TEMP_DIR}"

	__info_msg "Setting up configure files ..."
	pushd "${CADDY_DIR}"

	mkdir -p "wwwhtml"
	echo "auth failed (apdog v${RANDOM:0:1}.${RANDOM:0:2}.$RANDOM, caddy $(./${CADDY_BIN} version | awk -F ' ' '{print $1}'))" > "wwwhtml/index.html"

	echo -e ":443, ${CONF_DOMAIN}
{
	tls ${CONF_EMAIL} {
		protocols tls1.2 tls1.3
		ciphers TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 TLS_RSA_WITH_AES_128_GCM_SHA256
	}

	header {
		Strict-Transport-Security \"max-age=15768000; preload\"
		X-XSS-Protection \"1; mode=block\"
		X-Content-Type-Options \"nosniff\"
		X-Frame-Options \"DENY\"
	}

	route {
		forward_proxy {
			basic_auth ${CONF_USER} ${CONF_PASS}
			hide_ip
			hide_via
			probe_resistance
		}
		file_server { root $PWD/wwwhtml }
	}
}" > "${CADDY_CONF}"

	cat <<-EOF > "${SERVICE_FILE}"
[Unit]
Description=NaiveCaddy
After=network-online.target
Wants=network-online.target systemd-networkd-wait-online.service

[Service]
User=root
Group=root

AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
LimitNOFILE=1048576
NoNewPrivileges=true

Environment="HOME=${CADDY_DIR}"
Environment="XDG_CONFIG_HOME=${CADDY_DIR}"
Environment="XDG_DATA_HOME=${CADDY_DIR}"

WorkingDirectory=${CADDY_DIR}
ExecStart=/usr/bin/env ${CADDY_DIR}/${CADDY_BIN} run
Restart=always

[Install]
WantedBy=multi-user.target
	EOF
	systemctl enable "${CADDY_BIN}"

	popd

	__info_msg "Setting firewall rules ..."
	if [ "${SYSTEM_OS}" == "RHEL" ]; then
		for i in {80,443}
		do
			firewall-cmd --permanent --zone=public --add-port="$i"/tcp
			firewall-cmd --permanent --zone=public --add-port="$i"/udp
			firewall-cmd --reload
		done
	else
		for i in {80,443}
		do
			ufw allow "$i"/tcp
			ufw allow "$i"/udp
			ufw reload
		done
	fi

	__info_msg "Starting NaiveCaddy ..."
	systemctl start "${CADDY_BIN}"
	__info_msg "Waiting for 5s ..."
	sleep 5s
	pidof "${CADDY_BIN}" > "/dev/null" || __error_msg "Failed to start NaiveCaddy, please check your configure."

	echo -e "\n\n"
	__success_msg "Installation is finished, see connection info below:"
	echo -e "${GREEN_BACK}${CONF_USER}:${CONF_PASS}@${CONF_DOMAIN}:443${DEFAULT_COLOR}"
}

function remove_naivecaddy() {
	[ ! -d "${CADDY_DIR}" ] && { __error_msg "NaiveCaddy is never installed."; exit 1; }

	__warning_msg "You are about to remove NaiveCaddy. Is that correct?"
		read -e -r -p 'Are you sure? [y/N]: ' COMFIRM_REMOVE
		case "${COMFIRM_REMOVE}" in
		[yY][eE][sS]|[yY])
			__info_msg "Stopping NaiveCaddy ..."
			systemctl stop "${CADDY_BIN}"

			__info_msg "Removing NaiveCaddy files ..."
			systemctl disable "${CADDY_BIN}"
			rm -f "${SERVICE_FILE}"
			rm -rf "${CADDY_DIR}"

			__info_msg "Setting firewall rules ..."
			if [ "${SYSTEM_OS}" == "RHEL" ]; then
				for i in {80,443}
				do
					firewall-cmd --permanent --zone=public --remove-port="$i"/tcp
					firewall-cmd --permanent --zone=public --remove-port="$i"/udp
					firewall-cmd --reload
				done
			else
				for i in {80,443}
				do
					ufw delete allow "$i"/tcp
					ufw delete allow "$i"/udp
					ufw reload
				done
			fi

			__success_msg "NaiveCaddy is removed."
			;;
		*)
			__error_msg "The action is canceled by user."
			exit 1
			;;
		esac
}

function start_stop_naivecaddy() {
	[ ! -d "${CADDY_DIR}" ] && { __error_msg "NaiveCaddy is never installed."; exit 1; }

	if pidof "${CADDY_BIN}" > "/dev/null"; then
		__info_msg "Stopping NaiveCaddy ..."
		systemctl stop "${CADDY_BIN}"
		__info_msg "Waiting for 5s ..."
		sleep 5s
		if pidof "${CADDY_BIN}" > "/dev/null"; then
			__error_msg "Failed to stop NaiveCaddy."
		else
			__success_msg "NaiveCaddy is stopped."
		fi
	else
		__info_msg "Starting NaiveCaddy ..."
		systemctl start "${CADDY_BIN}"
		__info_msg "Waiting for 5s ..."
		sleep 5s
		if pidof "${CADDY_BIN}" > "/dev/null"; then
			__success_msg "NaiveCaddy is started."
		else
			__error_msg "Failed to start NaiveCaddy."
		fi
	fi
}

function restart_naivecaddy() {
	[ ! -d "${CADDY_DIR}" ] && { __error_msg "NaiveCaddy is never installed."; exit 1; }

	__info_msg "Restarting NaiveCaddy ..."
	systemctl restart "${CADDY_BIN}"
	__info_msg "Waiting for 5s ..."
	sleep 5s
	if pidof "${CADDY_BIN}" > "/dev/null"; then
		__success_msg "NaiveCaddy is restarted."
	else
		__error_msg "Failed to restart NaiveCaddy."
	fi
}

function main() {
	base_check
	check_status
	print_menu
}

main
