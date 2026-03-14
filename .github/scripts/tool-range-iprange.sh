#!/bin/bash

# #
#   @script             Blocklist › Range Converter (iprange)
#   @repo               https://github.com/ConfigServer-Software/service-blocklists
#   @workflow           blocklist-generate.yml
#   @type               Bash script
#   
#   @summary            Convert IPv4 start-end ranges to CIDR blocks using `iprange`,
#                           then output cleaned, deduped, counted ipset format.
#                           Source supports local file path or URL.
#   
#   @usage              .github/scripts/tool-range-iprange.sh
#                           <argFileSaveto>     str         required
#                           <argSourceFile>     str         required
#                           <argGrepFilter>     str         optional            default: '^#|^;|^$'
# #

# #
#   Define › Set PATH
# #

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
export LC_NUMERIC=en_US.UTF-8

# #
#   Define › Files
# #

app_file_this=$(basename "$0")                                                  # tool-range-iprange.sh (with ext)
app_file_bin="${app_file_this%.*}"                                              # tool-range-iprange    (without ext)

# #
#   Define › Folders
# #

app_dir="$(cd "$(dirname "$0")" >/dev/null 2>&1 && pwd)"                        # path where script was last found in
app_dir_this_dir="${PWD}"                                                       # current script directory
app_dir_github="${app_dir_this_dir}/.github"                                    # .github folder

# #
#   Define › Arguments
# #

argFileSaveto=$1
argSourceFile=$2
argGrepFilter=${3:-'^#|^;|^$'}

# #
#   Define › Colors
# #

esc=$(printf '\033')
end="${esc}[0m"
bgEnd="${esc}[49m"
fgEnd="${esc}[39m"
bold="${esc}[1m"
dim="${esc}[2m"
underline="${esc}[4m"
blink="${esc}[5m"
white="${esc}[97m"
black="${esc}[0;30m"
redl="${esc}[0;91m"
redd="${esc}[38;5;196m"
magental="${esc}[38;5;197m"
magentad="${esc}[38;5;161m"
fuchsial="${esc}[38;5;206m"
fuchsiad="${esc}[38;5;199m"
bluel="${esc}[38;5;33m"
blued="${esc}[38;5;27m"
greenl="${esc}[38;5;47m"
greend="${esc}[38;5;35m"
orangel="${esc}[38;5;208m"
oranged="${esc}[38;5;202m"
yellowl="${esc}[38;5;226m"
yellowd="${esc}[38;5;214m"
greyl="${esc}[38;5;250m"
greym="${esc}[38;5;244m"
greyd="${esc}[38;5;240m"
navy="${esc}[38;5;62m"
olive="${esc}[38;5;144m"
peach="${esc}[38;5;204m"
cyan="${esc}[38;5;6m"
bgVerbose="${esc}[1;38;5;15;48;5;125m"
bgDebug="${esc}[1;38;5;15;48;5;237m"
bgInfo="${esc}[1;38;5;15;48;5;27m"
bgOk="${esc}[1;38;5;15;48;5;64m"
bgWarn="${esc}[1;38;5;16;48;5;214m"
bgDanger="${esc}[1;38;5;15;48;5;202m"
bgError="${esc}[1;38;5;15;48;5;160m"

# #
#   Define › App
# #

app_name="Blocklist › Range Source"
app_desc="Fetch list of IPv4 ranges and convert to CIDR using iprange"
app_ver="1.2.0.0"
app_repo="configserver-software/service-blocklists"
app_repo_branch="main"
app_agent="Mozilla/5.0 (Windows NT 10.0; WOW64) "\
"AppleWebKit/537.36 (KHTML, like Gecko) "\
"Chrome/51.0.2704.103 Safari/537.36"

# #
#   Define › Args
# #

argDryrun="false"
argDevMode="false"
argVerbose="false"
argIncludeBogon="false"

# #
#   Define › Time
# #

time_start=$( date +%s )
SECONDS=0

# #
#   Define › Regex
# #

regex_url='^(https?|ftp|file)://[-A-Za-z0-9\+&@#/%?=~_|!:,.;]*[-A-Za-z0-9\+&@#/%=~_|]\.[-A-Za-z0-9\+&@#/%?=~_|!:,.;]*[-A-Za-z0-9\+&@#/%=~_|]$'
regex_ipv4='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
regex_ipv4_cidr='^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]{1,2})$'
regex_ipv6='^[0-9A-Fa-f:.]+$'
regex_ipv6_cidr='^[0-9A-Fa-f:.]+/[0-9]{1,3}$'
regex_ipv4_range='([0-9]{1,3}\.){3}[0-9]{1,3}[[:space:]]*-[[:space:]]*([0-9]{1,3}\.){3}[0-9]{1,3}'

# #
#   Define › Defaults
# #

total_lines=0
total_subnets=0
total_ips=0

# #
#   Define › Logging functions
# #

info( )
{
    printf '\033[0m%-41s %-65s\n' "   ${bgInfo} INFO ${end}" "${greym} $1 ${end}"
}

ok( )
{
    printf '\033[0m%-41s %-65s\n' "   ${bgOk} PASS ${end}" "${greym} $1 ${end}"
}

warn( )
{
    printf '\033[0m%-42s %-65s\n' "   ${bgWarn} WARN ${end}" "${greym} $1 ${end}"
}

danger( )
{
    printf '\033[0m%-42s %-65s\n' "   ${bgDanger} DNGR ${end}" "${greym} $1 ${end}"
}

error( )
{
    printf '\033[0m%-42s %-65s\n' "   ${bgError} FAIL ${end}" "${greym} $1 ${end}"
}

debug( )
{
    if [ "$argDevMode" = "true" ] || [ "$argDryrun" = "true" ]; then
        printf '\033[0m%-42s %-65s\n' "   ${bgDebug} DBUG ${end}" "${greym} $1 ${end}"
    fi
}

verbose( )
{
    case "${argVerbose:-0}" in
        1|true|TRUE|yes|YES)
            printf '\033[0m%-42s %-65s\n' "   ${bgVerbose} VRBO ${end}" "${greym} $1 ${end}"
            ;;
    esac
}

label( )
{
    printf '\033[0m%-31s %-65s\n' "   ${greyd}        ${end}" "${greyd} $1 ${end}"
}

print( )
{
    echo "${greym}$1${end}"
}

# #
#   Verify › Arguments
# #

if [ -z "${argFileSaveto}" ]; then
    error "    ⭕  No target file specified ${yellowd}${app_file_this}${greym}; aborting${end}"
    exit 0
fi

if [ -z "${argSourceFile}" ]; then
    error "    ⭕  No source file/url specified for ${yellowd}${argFileSaveto}${greym}; aborting${end}"
    exit 0
fi

case "${argSourceFile}" in
    http://*|https://*|ftp://*|file://*)
        ;;
    *)
        if [ ! -f "${argSourceFile}" ]; then
            error "    ⭕  Invalid source file specified ${yellowd}${argSourceFile}${greym}; aborting${end}"
            exit 0
        fi
        ;;
esac

if ! command -v iprange >/dev/null 2>&1; then
    error "    ⭕  Required binary ${yellowd}iprange${greym} not found in PATH; aborting${end}"
    exit 0
fi

# #
#   Print › Box › Paragraph
# #

prinp( )
{
    _title="$1"
    shift
    _text="$*"
    _indent="  "
    _box_width=110
    _pad=1
    _content_width=$(( _box_width ))
    _inner_width=$(( _box_width - _pad*2 ))
    _hline=$(printf '─%.0s' $(seq 1 "$_content_width"))
    _emoji_adjust=0

    print
    print
    printf "${greyd}%s┌%s┐\n" "$_indent" "$_hline"

    _display_title="$_title"
    if printf '%s\n' "$_title" | grep -q '\[[[:space:]]*[-0-9][-0-9[:space:]]*\]'; then
        _bracket=$(printf '%s' "$_title" | sed -n 's/.*\[\([-0-9][-0-9]*\)\].*/\1/p')
        if printf '%s\n' "$_bracket" | grep -qE '^-?[0-9]+$'; then
            _emoji_adjust=$_bracket
        else
            _emoji_adjust=0
        fi
        _display_title=$(printf '%s' "$_title" | sed 's/\[[^]]*\]//')
    fi

    case "$_emoji_adjust" in
        ''|*[!0-9-]*) _emoji_adjust=0 ;;
    esac

    _title_width=$(( _content_width - _pad ))
    _title_vis_len=$(( ${#_display_title} - _emoji_adjust ))
    printf "${greyd}%s│%*s${bluel}%s${greyd}%*s│\n" \
        "$_indent" "$_pad" "" "$_display_title" "$(( _title_width - _title_vis_len ))" ""

    if [ -n "$_text" ]; then
        printf "${greyd}%s│%-${_content_width}s│\n" "$_indent" ""
        _text=$(printf "%b" "$_text")
        printf "%s" "$_text" | while IFS= read -r line || [ -n "$line" ]; do
            if [ -z "$line" ]; then
                printf "${greyd}%s│%-*s│\n" "$_indent" "$_content_width" ""
                continue
            fi

            _out=""
            for word in $line; do
                _vis_out=$(printf "%s" "$_out" | sed 's/\x1B\[[0-9;]*[A-Za-z]//g')
                _vis_word=$(printf "%s" "$word" | sed 's/\x1B\[[0-9;]*[A-Za-z]//g')
                _vis_len=$(( ${#_vis_out} + ( ${#_vis_out} > 0 ? 1 : 0 ) + ${#_vis_word} ))

                if [ -z "$_out" ]; then
                    _out="$word"
                elif [ $_vis_len -le $_inner_width ]; then
                    _out="$_out $word"
                else
                    _vis_len_full=$(printf "%s" "$_out" | sed 's/\x1B\[[0-9;]*[A-Za-z]//g' | wc -c | tr -d ' ')
                    _pad_spaces=$(( _inner_width - _vis_len_full ))
                    [ $_pad_spaces -lt 0 ] && _pad_spaces=0
                    printf "${greyd}%s│%*s%s%*s│\n" "$_indent" "$_pad" "" "$_out" "$(( _pad + _pad_spaces ))" ""
                    _out="$word"
                fi
            done

            if [ -n "$_out" ]; then
                _vis_len_full=$(printf "%s" "$_out" | sed 's/\x1B\[[0-9;]*[A-Za-z]//g' | wc -c | tr -d ' ')
                _pad_spaces=$(( _inner_width - _vis_len_full ))
                [ $_pad_spaces -lt 0 ] && _pad_spaces=0
                printf "${greyd}%s│%*s%s%*s│\n" "$_indent" "$_pad" "" "$_out" "$(( _pad + _pad_spaces ))" ""
            fi
        done
    fi

    printf "${greyd}%s└%s┘${end}\n" "$_indent" "$_hline"
    print

    unset _title _text _indent _box_width _pad _content_width _inner_width _hline \
          _emoji_adjust _display_title _bracket _title_width _title_vis_len \
          _out _vis_out _vis_word _vis_len _vis_len_full _pad_spaces
}

# #
#   Define › Run Command
# #

run( )
{
    if [ "${argDryrun}" = "true" ]; then
        debug "    Drymode (skip): $*"
    else
        debug "    Run: $*"
        "$@"
    fi
}

# #
#   Sort Results
# #

sort_results( )
{
    _ipv4_tmp=$(mktemp) || exit 1
    _ipv6_tmp=$(mktemp) || exit 1

    while IFS= read -r line; do
        case "$line" in
            *:*) printf '%s\n' "$line" >> "$_ipv6_tmp" ;;
            *)   printf '%s\n' "$line" >> "$_ipv4_tmp" ;;
        esac
    done

    if [ -s "$_ipv4_tmp" ]; then
        sort -t. -n -k1,1 -k2,2 -k3,3 -k4,4 "$_ipv4_tmp" | uniq
    fi

    if [ -s "$_ipv6_tmp" ]; then
        sort "$_ipv6_tmp" | uniq
    fi

    rm -f "$_ipv4_tmp" "$_ipv6_tmp"
    unset _ipv4_tmp _ipv6_tmp
}

# #
#   Count file statistics
#       - IPv4 CIDR contributes all IPv4 addresses in the subnet
#       - IPv6 CIDR contributes one entry (do not expand)
#       - Single IPv4/IPv6 contributes one entry
# #

count_ip_stats( )
{
    _fnCountFile=$1
    _fnSubnetIps=0
    _fnTotalIps=0
    _fnTotalSubnets=0

    while IFS= read -r _fnLine; do

        # #
        #   IPv4 CIDR
        # #

        if [[ $_fnLine =~ $regex_ipv4_cidr ]]; then
            _fnCidr="${BASH_REMATCH[2]}"
            if [ "$_fnCidr" -le 32 ]; then
                _fnSubnetIps=$(( 1 << (32 - _fnCidr) ))
                _fnTotalIps=$(( _fnTotalIps + _fnSubnetIps ))
                _fnTotalSubnets=$(( _fnTotalSubnets + 1 ))
            fi

        # #
        #   IPv4 single
        # #
        elif [[ $_fnLine =~ $regex_ipv4 ]]; then
            _fnTotalIps=$(( _fnTotalIps + 1 ))

        # #
        #   IPv6 CIDR (count as one entry, do not expand)
        # #
        elif [[ $_fnLine =~ $regex_ipv6_cidr ]]; then
            _fnCidr="${_fnLine#*/}"
            if [ "$_fnCidr" -le 128 ]; then
                _fnTotalIps=$(( _fnTotalIps + 1 ))
                _fnTotalSubnets=$(( _fnTotalSubnets + 1 ))
            fi

        # #
        #   IPv6 single
        # #
        elif [[ $_fnLine =~ $regex_ipv6 ]] && [[ $_fnLine == *:* ]]; then
            _fnTotalIps=$(( _fnTotalIps + 1 ))
        fi
    done < "${_fnCountFile}"

    total_ips=$_fnTotalIps
    total_subnets=$_fnTotalSubnets

    unset _fnCountFile _fnSubnetIps _fnTotalIps _fnTotalSubnets _fnLine _fnCidr
}

# #
#   IPSET › Filter BOGON › IPv4
# #

is_bogon_ipv4( )
{
    _fnBogonIp=$1

    case "${_fnBogonIp}" in
        0.*|10.*|127.*|127.0.53.53|169.254.*|192.168.*|255.255.255.255) return 0 ;;
        100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*)   return 0 ;;
        172.1[6-9].*|172.2[0-9].*|172.3[0-1].*)                           return 0 ;;
        192.0.0.*|192.0.2.*|198.18.*|198.19.*|198.51.100.*|203.0.113.*)  return 0 ;;
        22[4-9].*|23[0-9].*|24[0-9].*|25[0-5].*)                          return 0 ;;
    esac

    return 1
}

# #
#   IPSET › Filter BOGON › IPv6
# #

is_bogon_ipv6( )
{
    _fnBogonIp="${1,,}"
    _fnBogonIp="${_fnBogonIp%%/*}"

    case "${_fnBogonIp}" in
        ::|::1|::ffff:*|::*)                                                         return 0 ;;
        100:*|100::*)                                                                return 0 ;;
        2001:1[0-9a-f]:*|2001:01[0-9a-f]:*|2001:001[0-9a-f]:*|2001:0001[0-9a-f]:*) return 0 ;;
        2001:db8:*|3fff:*|fc*|fd*|fe8*|fe9*|fea*|feb*|fec*|fed*|fee*|fef*|ff*)     return 0 ;;
    esac

    return 1
}

# #
#   IPSET › Filter BOGON Addresses
# #

filter_bogon_ips( )
{
    _fnBogonFile=$1
    _fnBogonTemp="${1}.bogon"
    _fnBogonLine=""
    _fnBogonBase=""
    _fnBogonBefore=0
    _fnBogonAfter=0
    _fnBogonRemoved=0

    case "${argIncludeBogon:-true}" in
        1|true|TRUE|yes|YES) return 0 ;;
    esac

    if [ ! -f "${_fnBogonFile}" ]; then
        warn "    ⚠️  Bogon filter skipped; file not found ${yellowl}${_fnBogonFile}${greym}"
        return 0
    fi

    info "    🚫 Filtering bogon IP ranges from ${bluel}${PWD}/${_fnBogonFile}${greym}"
    _fnBogonBefore=$(wc -l < "${_fnBogonFile}")
    > "${_fnBogonTemp}"

    while IFS= read -r _fnBogonLine || [ -n "${_fnBogonLine}" ]; do
        [ -z "${_fnBogonLine}" ] && continue
        _fnBogonBase="${_fnBogonLine%%/*}"

        if [[ "${_fnBogonBase}" == *:* ]]; then
            if is_bogon_ipv6 "${_fnBogonLine}"; then
                _fnBogonRemoved=$(( _fnBogonRemoved + 1 ))
                continue
            fi
        elif [[ "${_fnBogonBase}" == *.* ]]; then
            if is_bogon_ipv4 "${_fnBogonBase}"; then
                _fnBogonRemoved=$(( _fnBogonRemoved + 1 ))
                continue
            fi
        fi

        printf '%s\n' "${_fnBogonLine}" >> "${_fnBogonTemp}"
    done < "${_fnBogonFile}"

    mv "${_fnBogonTemp}" "${_fnBogonFile}"
    _fnBogonAfter=$(wc -l < "${_fnBogonFile}")
    ok "    🚫 Removed ${greenl}${_fnBogonRemoved}${greym} bogon entries from ${bluel}${PWD}/${_fnBogonFile}${greym}"

    unset _fnBogonFile _fnBogonTemp _fnBogonLine _fnBogonBase _fnBogonBefore _fnBogonAfter _fnBogonRemoved _fnBogonIp
}

# #
#   Func › Download List
# #

download_list( )
{
    _fnArgSource=$1
    _fnArgFile=$2
    _fnArgFilter=$3
    _fnListNum=$4
    _fnFileTemp="${2}.tmp"
    _fnFileRaw="${2}.raw"
    _fnFileSrc="${2}.src"
    _count_total_ips=0
    _count_total_subnets=0

    prinp "📄[-1] Processing list #${_fnListNum}"

    if [ ! -f "${_fnFileTemp}" ]; then
        touch "${_fnFileTemp}"
        if [ -f "${_fnFileTemp}" ]; then
            ok "    📄 Created temp file ${greenl}${PWD}/${_fnFileTemp}${greym}"
        else
            error "    ⭕ Failed to create temp file ${bluel}${PWD}/${_fnFileTemp}${greym}"
            exit 1
        fi
    fi

    # #
    #   Supports:
    #       - Direct URL to gzip file
    #           If specifying a web url to a gz file; must enclose the URL in quotes.
    #           In bash, the char & makes the previous command run in the background.
    #       - Local gzip file
    # #

    case "${_fnArgSource}" in
        http://*|https://*|ftp://*|file://*)
            info "    🌎 Downloading source ${bluel}${_fnFileRaw}${greym} ranges to ${bluel}${_fnFileRaw}${greym}"
            curl -sSL -k -A "${app_agent}" "${_fnArgSource}" -o "${_fnFileRaw}"
            ;;
        *)
            info "    📒 Reading local source ${bluel}${_fnArgSource}${greym}"
            cat "${_fnArgSource}" > "${_fnFileRaw}"
            ;;
    esac

    # #
    #   Check file type via magic bytes
    # #

    _file_type=$(file -b "${_fnFileRaw}")

    # #
    #   Compressed or local data
    # #

    if echo "${_file_type}" | grep -q 'gzip compressed data'; then
        info "    📦 Source appears gzip compressed; decompressing"
        gzip -dc "${_fnFileRaw}" > "${_fnFileSrc}"
    else
        info "    📦 Source not compressed; moving from ${bluel}${_fnFileRaw}${greym} to ${bluel}${_fnFileSrc}${greym}"
        cat "${_fnFileRaw}" > "${_fnFileSrc}"
    fi

    # #
    #   Filter specified
    # #

    if [ -n "${_fnArgFilter}" ]; then
        info "    📦 Grep filter specified: filtering ${bluel}${_fnArgFilter}${greym} in ${bluel}${_fnFileSrc}${greym} to ${bluel}${_fnFileSrc}.grep${greym}"
        grep -viE "${_fnArgFilter}" "${_fnFileSrc}" > "${_fnFileSrc}.grep" 2>/dev/null || cat "${_fnFileSrc}" > "${_fnFileSrc}.grep"
    else
        info "    📑 Grep filter not specified: copying ${bluel}${_fnFileSrc}${greym} to ${bluel}${_fnFileSrc}.grep${greym}"
        cat "${_fnFileSrc}" > "${_fnFileSrc}.grep"
    fi

    info "    🔁 Converting IPv4 ranges to CIDR with ${yellowl}iprange${greym}"
    grep -vE '^[[:space:]]*(#|;|$)' "${_fnFileSrc}.grep" \
        | grep -oE "${regex_ipv4_range}" \
        | sed 's/[[:space:]]*-[[:space:]]*/-/g' \
        | iprange > "${_fnFileTemp}" 2>/dev/null

    sed -i 's/\r$//' "${_fnFileTemp}"
    sed -i 's/-.*//' "${_fnFileTemp}"
    sed -i 's/[[:space:]]*[#;].*$//' "${_fnFileTemp}"
    sed -i 's/[[:space:]]\+/ /g' "${_fnFileTemp}"
    sed -i 's/^[[:space:]]*//;s/[[:space:]]*$//' "${_fnFileTemp}"
    sed -i '/^$/d' "${_fnFileTemp}"

    filter_bogon_ips "${_fnFileTemp}"

    info "    📊 Fetching statistics for clean file ${bluel}${PWD}/${_fnFileTemp}${greym}"

    count_ip_stats "${_fnFileTemp}"

    _count_total_ips=$total_ips
    _count_total_ips=$(printf "%'d" "$_count_total_ips")

    _count_total_subnets=$total_subnets
    _count_total_subnets=$(printf "%'d" "$_count_total_subnets")

    info "    🚛 Move ${bluel}${_fnFileTemp}${greym} to ${bluel}${_fnArgFile}${greym}"

    if [ -s "${_fnArgFile}" ] && [ "$(tail -c1 "${_fnArgFile}")" != "" ]; then
        echo >> "${_fnArgFile}"
    fi

    cat "${_fnFileTemp}" >> "${_fnArgFile}"
    rm -f "${_fnFileTemp}" "${_fnFileRaw}" "${_fnFileSrc}" "${_fnFileSrc}.grep"

    ok "    ➕ Added ${greenl}${_count_total_ips}${greym} IP addresses and ${greenl}${_count_total_subnets}${greym} subnets to ${greenl}${PWD}/${_fnArgFile}${greym}"

    unset _fnArgSource _fnArgFile _fnArgFilter _fnListNum _fnFileTemp _fnFileRaw _fnFileSrc \
          _count_total_ips _count_total_subnets
}

# #
#   Define › App
# #

file_ipset_temp="${argFileSaveto}.tmp"
file_ipset_target="${argFileSaveto}"

# #
#   Define › Template
# #

templ_now="$(date -u)"
templ_id=$(basename -- "${file_ipset_target}")
templ_id="${templ_id//[^[:alnum:]]/_}"
templ_uuid="$(uuidgen -m -N "${templ_id}" -n @url)"
templ_curl_opts=(-sSL -A "$app_agent")

# #
#   Define › Template › External Sources
# #

curl "${templ_curl_opts[@]}" "https://raw.githubusercontent.com/${app_repo}/${app_repo_branch}/.github/descriptions/${templ_id}.txt" > desc.txt &
curl "${templ_curl_opts[@]}" "https://raw.githubusercontent.com/${app_repo}/${app_repo_branch}/.github/categories/${templ_id}.txt" > cat.txt &
curl "${templ_curl_opts[@]}" "https://raw.githubusercontent.com/${app_repo}/${app_repo_branch}/.github/expires/${templ_id}.txt" > exp.txt &
curl "${templ_curl_opts[@]}" "https://raw.githubusercontent.com/${app_repo}/${app_repo_branch}/.github/url-source/${templ_id}.txt" > src.txt &
wait
templ_desc=$(<desc.txt)
templ_cat=$(<cat.txt)
templ_exp=$(<exp.txt)
templ_url_service=$(<src.txt)
rm -f desc.txt cat.txt exp.txt src.txt

# #
#   Define › Template › Default Values
# #

case "$templ_desc" in *"404: Not Found"*) templ_desc="#   No description provided";; esac
case "$templ_cat" in *"404: Not Found"*) templ_cat="Uncategorized";; esac
case "$templ_exp" in *"404: Not Found"*) templ_exp="6 hours";; esac
case "$templ_url_service" in *"404: Not Found"*) templ_url_service="None";; esac

# #
#   Output › Header
# #

echo
prinp "📄[-1] ${file_ipset_target}" \
"${greym}File: \t    ${greyd}.............${yellowl} ${file_ipset_target}${greyd} \
${greyd}\n${greym}Id: \t    ${greyd}...............${yellowl} ${templ_id}${greyd} \
${greyd}\n${greym}UUID:\t        ${greyd}.............${yellowl} ${templ_uuid}${greyd} \
${greyd}\n${greym}Category:\t        ${greyd}.........${yellowl} ${templ_cat}${greyd} \
${greyd}\n${greym}Script:\t       ${greyd}...........${yellowl} ${app_file_this}${greyd} \
${greyd}\n${greym}Service:\t        ${greyd}..........${yellowl} ${templ_url_service}${greyd}"

# #
#   Start
# #

info "    ⭐ Starting script ${bluel}${app_file_this}${greym}"

# #
#   Create or Clean file
# #

if [ -f "${file_ipset_target}" ]; then
    info "    📄 Clean ${bluel}${PWD}/${file_ipset_target}${greym}"
   > "${file_ipset_target}"
else
    info "    📁 Create ${bluel}${PWD}/${file_ipset_target}${greym}"
    mkdir -p "$(dirname "${file_ipset_target}")"

    if [ -d "$(dirname "${file_ipset_target}")" ]; then
        ok "    📁 Created ${greenl}$(dirname "${file_ipset_target}")${greym}"
    else
        error "    ⭕  Failed to create directory ${redl}$(dirname "${file_ipset_target}")${greym}; aborting${greym}"
        exit 1
    fi

    touch "${file_ipset_target}"
    if [ -f "${file_ipset_target}" ]; then
        ok "    📄 Created perm file ${greenl}${PWD}/${file_ipset_target}${greym}"
    else
        error "    ⭕ Failed to create perm file ${bluel}${PWD}/${file_ipset_target}${greym}"
        exit 1
    fi
fi

# #
#   Download list
# #

i=1
download_list "${argSourceFile}" "${file_ipset_target}" "${argGrepFilter}" "${i}"

# #
#   Sort
#       - Remove downloaded comment/blank lines
#       - Sort/dedupe IPv4 and IPv6 separately
# #

if [ -f "${file_ipset_target}" ]; then
    info "    🧹 Sorting and removing duplicate IP entries from ${bluel}${PWD}/${file_ipset_target}${greym}"
    grep -vE '^[[:space:]]*(#|;|$)' "${file_ipset_target}" | sort_results > "${file_ipset_target}.sort"
    > "${file_ipset_target}"
    cat "${file_ipset_target}.sort" >> "${file_ipset_target}"
    rm "${file_ipset_target}.sort"
    ok "    ✅ Duplicate IPs removed"
fi

# #
#   Final Counts (from final cleaned + deduped file)
# #

if [ -f "${file_ipset_target}" ]; then
    count_ip_stats "${file_ipset_target}"
    total_ips=$total_ips
    total_subnets=$total_subnets

    total_lines=$(wc -l < "${file_ipset_target}")
    total_lines=$(printf "%'d" "$total_lines")
    total_subnets=$(printf "%'d" "$total_subnets")
    total_ips=$(printf "%'d" "$total_ips")
fi

# #
#   Template › Header
# #

ed -s "${file_ipset_target}" <<END_ED
0a
# #
#   🧱 Firewall Blocklist - ${file_ipset_target}
#
#   @repo           https://raw.githubusercontent.com/${app_repo}/${app_repo_branch}/${file_ipset_target}
#   @service        ${templ_url_service}
#   @id             ${templ_id}
#   @uuid           ${templ_uuid}
#   @updated        ${templ_now}
#   @entries        ${total_ips} ips
#                   ${total_subnets} subnets
#                   ${total_lines} lines
#   @expires        ${templ_exp}
#   @category       ${templ_cat}
#
${templ_desc}
# #

.
w
q
END_ED

# #
#   Finished
# #

time_end=$( date +%s )
T=$(( time_end - time_start ))
D=$(( T / 86400 ))
H=$(( (T % 86400) / 3600 ))
M=$(( (T % 3600) / 60 ))
S=$(( T % 60 ))

# #
#   Output › Footer
# #

prinp "🎌[-1] Blocklist has finished generating successfully" \
"${greyd}${greym}IPs: \t    ${greyd}............${yellowl} ${total_ips}${greyd} \
${greyd}\n${greym}Subnets:\t        ${greyd}........${yellowl} ${total_subnets}${greyd} \
${greyd}\n${greym}Duration:\t        ${greyd}.......${yellowd} ${D} days ${H} hrs ${M} mins ${S} secs${greyd}"
