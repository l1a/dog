_dog()
{
    cur=${COMP_WORDS[COMP_CWORD]}
    prev=${COMP_WORDS[COMP_CWORD-1]}

    case "$prev" in
        -'?'|--help|-v|--version)
            return
            ;;

        -t|--type)
            COMPREPLY=( $( compgen -W 'A AAAA ANAME ANY AXFR CAA CDNSKEY CDS CNAME CSYNC DNSKEY DS HINFO HTTPS IXFR KEY MX NAPTR NS NSEC NSEC3 NSEC3PARAM NULL OPENPGPKEY OPT PTR RRSIG SIG SOA SRV SSHFP SVCB TLSA TSIG TXT' -- "$cur" ) )
            return
            ;;

        --edns)
            COMPREPLY=( $( compgen -W 'disable hide show' -- "$cur" ) )
            return
            ;;

        -Z)
            COMPREPLY=( $( compgen -W 'aa ad bufsize= cd' -- "$cur" ) )
            return
            ;;

        --class)
            COMPREPLY=( $( compgen -W 'IN CH HS' -- "$cur" ) )
            return
            ;;

        --color|--colour)
            COMPREPLY=( $( compgen -W 'always automatic never' -- $cur ) )
            return
            ;;
    esac

    case "$cur" in
        -*)
            COMPREPLY=( $( compgen -W '$( _parse_help "$1" )' -- "$cur" ) )
            return
            ;;

        *)
            COMPREPLY=( $( compgen -W 'A AAAA ANAME ANY AXFR CAA CDNSKEY CDS CNAME CSYNC DNSKEY DS HINFO HTTPS IXFR KEY MX NAPTR NS NSEC NSEC3 NSEC3PARAM NULL OPENPGPKEY OPT PTR RRSIG SIG SOA SRV SSHFP SVCB TLSA TSIG TXT' -- "$cur" ) )
            ;;
    esac
} &&
complete -o bashdefault -F _dog dog
