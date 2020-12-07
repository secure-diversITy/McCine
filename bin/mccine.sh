#!/bin/bash
#########################################################################################
#
# Generates/Uses a custom CA and self-sign certs with alternate names / multiple CNs.
#
# "mccine": [m]ulti [c]ert [c]reator [i]s [n]ot [e]asy-rsa ;o)
#
#########################################################################################
#
# Author: Thomas Fischer
# License:CC BY-ND 3.0 ( http://creativecommons.org/licenses/by-nd/3.0 )
VERSION=2020-12-07
#
#############################################################################

# cert req defaults 
DEFSIGNENC="sha256" # the SHA signature hash to be used. Do NOT use sha1 for public certs!

# root ca defaults
DEFCADAYS=4380		# default duration for the CA cert in days (4380 means 12 years)
DEFCERTDAYS=2190	# default duration for the signed cert in days (2190 means 6 years)
DEFCABITS=8192		# Strength of enryption key (in bits) for the ROOT-CA
DEFCERTBITS=4096	# Strength of enryption key (in bits) for the certificate private key

# sub ca defaults
DEFSCADAYS=2190      # default duration for the CA cert in days (2190 means 6 years)
DEFSCERTDAYS=1460    # default duration for the signed cert in days (1460 means 4 years)
DEFSCABITS=8192      # Strength of enryption key (in bits) for the SUB-CA
DEFSCERTBITS=4096    # Strength of enryption key (in bits) for the certificate private key

# main config file for openssl
OPENSSLCACONF=$PWD/etc/openssl_CA.cnf
OPENSSLSCACONF=$PWD/etc/openssl_SUBCA.cnf
OPENSSLMAILCONF=$PWD/etc/openssl_MAIL.cnf
OPENSSLCONF=$PWD/etc/openssl_CAmulti.cnf

# cert folders - ensure that they are matching OPENSSLCONF!
CADIR=$PWD/CA
ROOTCADIR=${CADIR}/root
SUBCADIR=${CADIR}/sub
NEWCRTDIR=$PWD/certs/
INDEX=$PWD/share/index.txt
SERIAL=$PWD/share/serial


# logfile
LOG=$PWD/log/mccine.log


# NO USER VARIABLES BEHIND THIS LINE - HERE STARTS THE CODE ;o)
###########################################################################################################

# echo function which can output on console or/and logfile
F_ECHOLOG(){
    MSG="$1"
    echo -e "$MSG" | tee -a $LOG
}

# clean log
echo "$(date) - starting new logfile." > $LOG

# basic conf check
if [ -z "$OPENSSLCACONF" ]||[ -z "$OPENSSLCONF" ];then echo "ERROR: REQUIRED CNF FILE VARIABLE IS EMPTY (check code). ABORTED" ; exit 1 ; fi
if [ ! -f "$OPENSSLCACONF" ]||[ ! -f "$OPENSSLCONF" ];then echo "ERROR: CANNOT OPEN REQUIRED FILE <$OPENSSLCACONF|$OPENSSLCONF>. ABORTED" ; exit 1; fi

# the basic help info
F_HELP(){ 
    # catches the -h only option
    F_HELP_ 
}
F_HELP_(){
    echo "  Version: $VERSION - by www.se-di.de"
    echo
    echo "  This will do stuff to easily self-sign multiple/alternative FQDN/IPs. It is NOT easy-rsa!"
    echo "  mccine can (easy-rsa can not) sign certs with multiple FQDNs/IPs and is not such comfortable as this tool ;o)."
    echo
    echo "  When you want >1< common name only you may (but don't need to) use easy-rsa instead."
    echo "  mccine can sign single CN's, too of course."
    echo
    echo "  Getting starting is VERY easy and done in 2 simple steps!"
    echo
    echo "   1) $0 -m CA -F my.CA-SERVER.com"
    echo
    echo "          You will be guided to the initial setup of your own and new CA"
    echo "          and you will get at the end an example output for the next step:"
    echo
    echo "   2) $0 -m sign -F my.main-servername.com,IamNOTaFQDN,1.1.1.1 -C my.ROOT-CA.pem -i my.ROOT-CA.crt"
    echo
    echo "          (You can copy & paste the ROOT-CA filenames right from step 1)"
    echo "          Again you will be guided to the whole process - this time for creating your new certificate"
    echo "          signed with the CA created in step 1 and with default options."
    echo
    echo "  You're done! Next time you need step <2> only because you already have a CA! Isn't that easy? :o)"
    echo "  More examples and the full help are available within the specific help sections."
    echo
    echo "  Usage:"
    echo "    $> $0 -m [MODE] [options]"
    echo 
    echo "  MODE = usage mode. can be one of: <ROOTCA> | <SUBCA> | <sign> | <csr>"
    echo 
    echo "  -h ROOTCA"
    echo "            <ROOTCA> will create a ROOT-CA and you need to start here when using mccine the first time."
    echo "  -h SUBCA"
    echo "            <SUBCA> requires a ROOT-CA! If you have one already choose this to create a signing SUB-CA."
    echo "  -h sign"
    echo "            <sign> requires a ROOT- or SUB-CA! This helps you in self-signing a user cert."
    echo "  -h csr"
    echo "            <csr> requires a FQDN/IP only. No self-signing here. Use this mode if you want to sign"
    echo "            your csr by another CA."
    echo "  -h full"
    echo "            will show all help output of the above."
    echo
}

# help info about the root-ca
F_HELP_CA(){
    echo
	echo "    MODE = <ROOTCA>"
	echo
    echo "    -m ROOTCA|CA|rootca|ca"
    echo
	echo "        The ROOT-CA mode will be used normally once only. It is not recommended to sign user certs with a ROOT-CA"
	echo "        and it is needed in order to create a SUB-CA (which then signing your certs)."
	echo "        If you already have a CA which is able to do that (check your openssl.cnf settings!) or if you"
	echo "        have created a ROOT-CA with this tool already you can skip that and proceed with <SUBCA> and / or <sign> mode."
	echo 
    echo "        (Order of args is totally free and case insensitive)"
    echo
	echo "        Required:"
	echo "           -f|F CA CN = Common name of your ROOT-CA cert, e.g the DNS name or IP address of the CA system"
	echo
    echo "        Optional:"
    echo "           -c|C CA PEM file = The private key file of the signing ROOT-CA"
    echo "           -d|D DAYS-FOR-SIGNING = How long should the cert be valid in days."
    echo "           -b|B CA KEY-STRENGTH = Defines the strength of the encryption key of the CA"
	echo
	echo "         Defaults:"
	echo "            DAYS-FOR-SIGNING = $DEFCADAYS days"
	echo "            CA KEY-STRENGTH = $DEFCABITS bit"
	echo "            CA PEM file = <CN defined by -F arg>.pem"
	echo
	echo "	       Examples:"
	echo "		  $> $0 -m ROOTCA -F my.CA-SERVER.com -C my.CA-server.pem -d 3650 -b 4096"
	echo "		  $> $0 -m CA -F my.CA-SERVER.com"
	echo
}

#help info for intermediate CA
F_HELP_SUBCA(){
    echo
    echo "    MODE = <SUBCA>"
    echo
    echo "    -m SUBCA|subca"
    echo    
    echo "        The SUBCA mode will be used normally once to create an intermediate CA for a specific purpose. "
    echo "        It then will be used to sign the user / mail / webservers certificates."
    echo "        Such a intermediate or SUB-CA is recommended and should be used to be secure."
    echo 
    echo "        (Order of args is totally free and case insensitive)"
    echo
    echo "        Required:"
    echo "           -f|F CA CN = Common name of your SUB-CA cert, e.g the DNS name or IP address of the SUBCA system"
    echo "           -r|R CA PEM file = The private key file of the signing ROOT-CA which will sign your cert-request"
    echo "           -i|I CA CERT file = The CA certificate file of the signing ROOT-CA."
    echo
    echo "        Optional:"
    echo "           -d|D DAYS-FOR-SIGNING = How long should the cert be valid in days."
    echo "           -b|B CA KEY-STRENGTH = Defines the strength of the encryption key of the CA"
    echo
    echo "         Defaults:"
    echo "            DAYS-FOR-SIGNING = $DEFSCADAYS days"
    echo "            CA KEY-STRENGTH = $DEFSCABITS bit"
    echo "            CA PEM file = <CN-you-defined-by -F arg>.pem"
    echo
    echo "         Examples:"
    echo "            $> $0 -m SUBCA -F my.subca.com -r my.ROOTca.pem -i my.ROOTca.crt"
    echo "            $> $0 -m SUBCA -F my.subca.com -r my.ROOTca.pem -i my.ROOTca.crt -d 3650 -b 4096"
    echo

}

# help info for signing certs
F_HELP_SIGN(){
    echo
    echo "    MODE = <sign>"
	echo
    echo "    -m SIGN|sign"
    echo        
	echo "         The sign mode will be your 'normal' operation mode once you have created your ROOT-CA and"
	echo "         will be used to self-sign your certs with the CA you created in MODE = <CA>."
	echo
    echo "        (Order of args is totally free and case insensitive)"
    echo
	echo "         Required:"
	echo "            -f|F MAIN-FQDN,CNx,IP1,IPx,... = One ore multiple common name(s) AND/OR IPs of the server certificate,"
    echo "                                             normally that will be the DNS name(s)/IP(s) of your target server."
	echo "            -c|C CA PEM file = The private key file of the signing ROOT-CA which will sign your cert-request"
    echo "            -i|I CA CERT file = The CA certificate file of the signing ROOT-CA."
	echo
	echo "         Optional:"
	echo "            -p|P CERT PEM file = The private key file of the existing/new server cert (will be created if not existing)"
	echo "            -d|D DAYS-FOR-SIGNING = How long should the cert be valid in days."
	echo "            -b|B CERT KEY-STRENGTH = Defines the strength of the private key"
    echo "            -s   mail|MAIL = you can define 'MAIL' as special signing mode and then create a S/MIME certificate"
        echo "            -A FULL-CA-CHAIN = Path to the full-chain CA file. Required when you are using a sub-CA only"
	echo
	echo "         Defaults:"
	echo "            CERT PEM file = <CN defined by -F arg>.pem"
	echo "            DAYS-FOR-SIGNING = $DEFCERTDAYS days"
	echo "            CERT KEY-STRENGTH = $DEFCERTBITS bit"
	echo
	echo
	echo "	       Examples:"	
    echo "             $> $0 -m sign -F my.ssl-server.de,myhostname,1.1.1.1 -C my.SUB-CA.pem -p my.CERT.pem -d 365 -b 2048 -i my.SUB-CA.crt"
	echo "             $> $0 -m sign -s MAIL -F support@se-di.de,info@se-di.de,info@sicherevielfalt.de -C my.SUB-CA.pem -i my.SUB-CA.crt"
    echo "             $> $0 -m sign -F my.ssl-server.de -C my.SUB-CA.pem -i my.SUB-CA.crt"    
	echo
	echo
}

# help info for creating cert requests
F_HELP_CSR(){
    echo
    echo "    MODE = <csr>"
	echo
    echo "    -m csr|req"
    echo        
	echo "         The csr mode will be used to create a new certificate request only!"
    echo "         It will NOT sign anything so you need to sign it manually or by another CA."
	echo
    echo "        (Order of args is totally free and case insensitive)"
    echo
	echo "         Required:"
	echo "            -f|F MAIN-FQDN,CNx,IP1,IPx,... = One ore multiple common name(s) AND/OR IPs of the server certificate,"
    echo "                                             normally that will be the DNS name(s)/IP(s) of your target server."
	echo
	echo "         Optional:"
	echo "            -p|P CERT PEM file = The private key file of the existing/new server cert (will be created if not existing)"
	echo "            -d|D DAYS-FOR-SIGNING = How long should the cert be valid in days."
	echo "            -b|B CERT KEY-STRENGTH = Defines the strength of the private key"
    echo "            -s   mail|MAIL = you can define 'MAIL' as special signing mode and then create a S/MIME certificate request"
	echo
	echo "         Defaults:"
	echo "            CERT PEM file = <CN defined by -F arg>.pem"
	echo "            DAYS-FOR-SIGNING = $DEFCERTDAYS days"
	echo "            CERT KEY-STRENGTH = $DEFCERTBITS bit"
	echo
	echo
	echo "	       Examples:"	
    echo "             $> $0 -m csr -F my.ssl-server.de,myhostname,1.1.1.1 -d 365 -b 2048"
	echo "             $> $0 -m csr -s MAIL -F support@se-di.de,info@se-di.de,info@sicherevielfalt.de"
    echo "             $> $0 -m csr -F my.ssl-server.de"    
	echo
	echo
}

#show all help info
F_HELP_FULL(){
    F_HELP
    F_HELP_CSR
    F_HELP_CA
    F_HELP_SUBCA
    F_HELP_SIGN
}

# check correct values which are the same for all modes - we do that here (and not in the getopt loop) to ensure that also the default values are checked!
F_COMMONCHKS(){
    [[ ! "$BITS" == ?(+|-)+([0-9]) ]] && F_ECHOLOG "ERROR: Key Strength >-b|B $BITS< contains invalid chars - use digits only (e.g. 1024)." && F_HELP && exit 2
    [[ ! "$CDAYS" == ?(+|-)+([0-9]) ]] && F_ECHOLOG "ERROR: Duration >-d|D $CDAYS< contains invalid chars - use the amount of days in digits only (e.g. 365)." && F_HELP && exit 2
}

# checks if the arg is a valid IP - shamelessly stolen ;o)
F_IPCHK(){
    local  ip=$1
    local  stat=1

    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=($ip)
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 \
            && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
    fi
    return $stat
}

# very generic check for a valid mail address. To have this simple is important and wanted to ensure we could
# use internal mail adresses for example. A real solution is near impossible because either you need
# to be in the internal network to find out if it is a working and really valid address or it will fail when using dig/mx tests etc.
# so we keep it simple here and hope you know what you're typing in ;-)
F_MAILCHK(){
    local email="$1"
    local estat=1

    if [[ "$email" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}$ ]];then
        estat=0
    else
        estat=2
    fi
    return $estat
}

# parse arguments
while getopts "h:H:f:F:c:C:b:B:d:D:m:M:i:I:r:R:s:A:" arg; do
  case "$arg" in
    [hH])
        [ ! -z ${OPTARG} ]&&HELPOPT=$(echo ${OPTARG} |tr [:lower:] [:upper:])
        F_HELP_$HELPOPT && exit 0
       ;;
    [fF])
      ALLCN="$OPTARG"
      MYCN=$(echo $ALLCN |cut -d "," -f1)
      F_ECHOLOG "Detected main common name: <$MYCN>"
      F_ECHOLOG "All detected common names: <$ALLCN>"
      ;;
    [dD]) 
      CDAYS=$OPTARG
      F_ECHOLOG "Detected duration: <$CDAYS>"
     ;;
    [cC]) 
      CAPEM=$OPTARG
      F_ECHOLOG "Detected CA file: <$CAPEM>"
     ;;
    [rR]) 
      RCAPEM=$OPTARG
      F_ECHOLOG "Detected Root-CA file: <$RCAPEM>"
     ;;     
    [bB])
      BITS=$OPTARG
      F_ECHOLOG "Detected Key strength: <$BITS>"
    ;;
    [mM])
      MODE=$OPTARG
      F_ECHOLOG "Detected operation mode: <$MODE>"
    ;;
    [iI])
      CACERT="$OPTARG"
      F_ECHOLOG "Detected CACERT: <$CACERT>"
    ;;
    [pP])
      PKEY=$OPTARG
      F_ECHOLOG "Detected private key file: <$PKEY>"
    ;;
    [s])
      SIGNMODE=$(echo $OPTARG |tr [:lower:] [:upper:])
      F_ECHOLOG "Detected signing mode: <$SIGNMODE>"
    ;;
    [A])
      CACHAIN="$OPTARG"
      F_ECHOLOG "Detected CA Chain file: <$CACHAIN>"
    ;;            
    \?)
      [ ! -z "$OPTARG" ] && F_ECHOLOG "Invalid option: -$OPTARG" >&2
      F_HELP
      exit 2
      ;;
  esac
done

# check mode
[ -z "$MODE" ]&& F_ECHOLOG "ERROR: < -m MODE > is always required!" && echo "Use $0 -h to find out how mccine works." && exit 2

case "$MODE" in
        rootca|ROOTCA|ca|CA) F_ECHOLOG "Running in >ROOTCA< mode." ; MODE=ROOTCA
            ###################################################################################
            ###                                                                             ###
            ### ROOT CA mode                                                                ###
            ###                                                                             ###
            ###################################################################################

            echo "Using settings from >$OPENSSLCACONF<" >> $LOG
            OPENSSL_CONF=$OPENSSLCACONF
            export OPENSSL_CONF

            # some checks and default options 
            if [ -z "$MYCN" ];then
                echo && F_ECHOLOG "ERROR: at least > -f|F < is required in this mode!" && echo && F_HELP_CA
                exit 2
            else
                # some basic checks and defaults
                [ -z "$BITS" ]&& BITS="${DEFCABITS}"
                [ -z "$CAPEM" ]&& CAPEM="${ROOTCADIR}/${MYCN}.pem"
                [ -f "$CAPEM" ]&& F_ECHOLOG "ERROR: CAPEM file already exists! ABORTED TO ENSURE WE DO NOT OVERWRITE A ROOT-CA!!!" && F_HELP_CA && exit 2
                [ -z "$CDAYS" ]&& F_ECHOLOG "Using default amount of days for signing ($DEFCADAYS days)" && CDAYS=$DEFCADAYS
                F_COMMONCHKS
            fi
            # Do the magic..

            echo "##########################################################"
            echo "# Creating private key:"
            echo
            #openssl genrsa -out ${CAPEM} $BITS -config $OPENSSLCACONF 2>&1 >>$LOG
            openssl genrsa -out ${CAPEM} $BITS 2>&1 >>$LOG
            [ $? -ne 0 ]&& F_ECHOLOG "ERROR: While creating CA private key. ABORTED!" && exit 2

            echo "##########################################################"
            echo "# Creating a request based on that private key:"
            echo
            openssl req -days $CDAYS -new -key ${CAPEM} -out ${ROOTCADIR}/${MYCN}_${CDAYS}-days.req.txt -config $OPENSSLCACONF 2>&1 >>$LOG
            [ $? -ne 0 ]&& F_ECHOLOG "ERROR: While creating CA cert request. ABORTED!" && exit 2

            echo "##########################################################"
            echo "# Self sign the request and therefore create the wanted CA:"
            echo
            openssl x509 -extfile $OPENSSLCACONF -extensions v3_ca -req -days $CDAYS -in ${ROOTCADIR}/${MYCN}_${CDAYS}-days.req.txt -signkey ${CAPEM} -out ${ROOTCADIR}/${MYCN}_${CDAYS}-days.crt 2>&1 >>$LOG
            [ $? -ne 0 ]&& F_ECHOLOG "ERROR: While signing CA cert request. ABORTED!" && exit 2

            echo "##########################################################"
            echo "# Your CA certificate:"
            echo
            openssl x509 -text -in ${ROOTCADIR}/${MYCN}_${CDAYS}-days.crt
            
            echo "##########################################################"
            F_ECHOLOG "# Your CA certificate HASH (e.g. for use in Android > v4):"
            echo
            CHASH=$(openssl x509 -noout -hash -in ${ROOTCADIR}/${MYCN}_${CDAYS}-days.crt)
            F_ECHOLOG "$CHASH"
            ln -sf ${MYCN}_${CDAYS}-days.crt ${ROOTCADIR}/$CHASH && F_ECHOLOG "Created hash link for the certificate for your convenience.."
            echo "##########################################################"
            echo
            echo "Congrats your CA is ready to use now!"
            echo
            echo "For signing a new certificate you need to execute now:"
            echo " $> $0 -m SIGN -f your-server-FQDN -C ${CAPEM} -i ${ROOTCADIR}/${MYCN}_${CDAYS}-days.crt (-h show you the full help/usage info)"
            echo
        ;;
        subca|SUBCA) F_ECHOLOG "Running in >SUBCA< mode." ; MODE=SUBCA
            ###################################################################################
            ###                                                                             ###
            ### INTERMEDIATE / SUB CA mode                                                  ###
            ###                                                                             ###
            ###################################################################################

            echo "Using settings from >$OPENSSLSCACONF<" >> $LOG
            cp $OPENSSLSCACONF ${OPENSSLSCACONF}.tmp
            OPENSSLCONF="${OPENSSLSCACONF}.tmp"
            OPENSSL_CONF=$OPENSSLSCACONF
            export OPENSSL_CONF

            # some checks and default options 
            if [ -z "$MYCN" ]||[ -z "$RCAPEM" ]||[ -z "$CACERT" ];then
                echo && F_ECHOLOG "ERROR: ALL of > -f|F AND -r|R AND -i|I < are required in this mode!" && echo && F_HELP_SUBCA
                exit 2
            else
                # some basic checks and defaults
                [ ! -f "$CACERT" ]&& F_ECHOLOG "ERROR: ROOT-CA not found! ABORTED!" && F_HELP_SUBCA && exit 2                
                [ -z "$BITS" ]&& BITS="${DEFSCABITS}"
                [ -z "$CAPEM" ]&& CAPEM="${SUBCADIR}/${MYCN}.pem"
                [ -f "$CAPEM" ]&& F_ECHOLOG "ERROR: CAPEM file already exists! ABORTED TO ENSURE WE DO NOT OVERWRITE A SUB-CA!!!" && F_HELP_SUBCA && exit 2
                [ -z "$CDAYS" ]&& F_ECHOLOG "Using default amount of days for signing ($DEFSCADAYS days)" && CDAYS=$DEFSCADAYS
                F_COMMONCHKS
            fi

            INDEX=${INDEX}_$MYCN
            SERIAL=${SERIAL}_$MYCN

            #preparing openssl stuff
            [ ! -f $INDEX ]&& >$INDEX
            [ ! -f $SERIAL ]&& echo "01" >$SERIAL


            echo "##########################################################"
            echo "# Creating private key:"
            echo
            #openssl genrsa -out ${CAPEM} $BITS -config $OPENSSLSCACONF 2>&1 >>$LOG
            openssl genrsa -out ${CAPEM} $BITS 2>&1 >>$LOG
            [ $? -ne 0 ]&& F_ECHOLOG "ERROR: While creating SUBCA private key. ABORTED!" && exit 2

            # preparing the special openssl conf

            # build the correct filenames for CA specific files
            sed -i "s/MCCINECA/$MYCN/g" $OPENSSLSCACONF

            # replace default common name with the main one
            sed -i "s/MCCINECN/$MYCN/g" $OPENSSLSCACONF
#            sed -i "/\[alt_names\]/ a\
#DNS.1=$MYCN" $OPENSSLCONF
            
            # set counters
            iCNT=1
            dCNT=2

            # add all the alternative names/ips
            for ALTN in $(echo "$ALLCN" |tr "," " ");do
                F_IPCHK "$ALTN"
                if [ $? -eq 0 ];then
                    echo "<$ALTN> seems to be a valid IP" >> $LOG
                    sed -i "/\[alt_names\]/ a\
IP.${iCNT}=$ALTN" $OPENSSLCONF && ((iCNT ++))
                else
                    echo "<$ALTN> seems to be not a valid IP therefore we handle it like DNS" >> $LOG
                    sed -i "/\[alt_names\]/ a\
DNS.${dCNT}=$ALTN" $OPENSSLCONF && ((dCNT ++))
                fi
            done

         echo "##########################################################"
            echo "# Creating a request based on that private key:"
            echo
            openssl req -days $CDAYS -new -key ${CAPEM} -out ${SUBCADIR}/${MYCN}_${CDAYS}-days.req.txt -config $OPENSSLSCACONF 2>&1 >>$LOG
            [ $? -ne 0 ]&& F_ECHOLOG "ERROR: While creating SUBCA cert request. ABORTED!" && exit 2

            echo "##########################################################"
            echo "# Sign the request and create the wanted subca:"
            echo
            # no redirection to log so we can see the sign y/n question:
            openssl x509 -extfile $OPENSSLSCACONF -extensions v3_ca -CA $CACERT -req -days $CDAYS -in ${SUBCADIR}/${MYCN}_${CDAYS}-days.req.txt -CAserial $SERIAL -CAkey ${RCAPEM} -out ${SUBCADIR}/${MYCN}_${CDAYS}-days.crt
#            openssl ca -extensions v3_ca -keyfile ${RCAPEM} -policy policy_anything -cert $CACERT -days $CDAYS -config $OPENSSLSCACONF -out ${SUBCADIR}/${MYCN}_${CDAYS}-days.crt -infiles ${SUBCADIR}/${MYCN}_${CDAYS}-days.req.txt
            [ $? -ne 0 ]&& F_ECHOLOG "ERROR: While signing cert request. ABORTED!" && exit 2
 
            echo "##########################################################"
            echo "# Your SUBCA certificate:"
            echo
            openssl x509 -text -in ${SUBCADIR}/${MYCN}_${CDAYS}-days.crt
            
            echo "##########################################################"
            F_ECHOLOG "# Your SUBCA certificate HASH (e.g. for use in Android > v4):"
            echo
            CHASH=$(openssl x509 -noout -hash -in ${SUBCADIR}/${MYCN}_${CDAYS}-days.crt)
            F_ECHOLOG "$CHASH"
            ln -sf ${MYCN}_${CDAYS}-days.crt ${SUBCADIR}/$CHASH && F_ECHOLOG "Created hash link for the certificate for your convenience.."            
            echo "##########################################################"
            echo "# Creating full CA chain..."
            cat ${SUBCADIR}/${MYCN}_${CDAYS}-days.crt $CACERT > ${SUBCADIR}/${MYCN}_${CDAYS}-days_fullCAchain.crt
            echo " Your full CA chain was created here: "
            echo " > ${SUBCADIR}/${MYCN}_${CDAYS}-days_fullCAchain.crt <" 
            echo "##########################################################"
            echo
            echo "Congrats your SUB-CA is ready to use now!"
            echo
            echo "For signing a new certificate you need to execute now:"
            echo " $> $0 -m sign -f your-server-FQDN -C ${CAPEM} -i ${SUBCADIR}/${MYCN}_${CDAYS}-days.crt "
            echo "  ($0 -h sign -> shows you the full help/usage info)"
            echo
        ;;        
        sign|SIGN) F_ECHOLOG "Running in >sign< mode." ; MODE=SIGN
            ###################################################################################
            ###                                                                             ###
            ### Certificate sign mode                                                       ###
            ###                                                                             ###
            ###################################################################################

            # we do not want to modify the template openssl config so we duplicate it first
            # and we do that depending on the signing mode
            if [ ! -z "$SIGNMODE" ] && [ "$SIGNMODE" == "MAIL" ];then
                cp $OPENSSLMAILCONF ${OPENSSLMAILCONF}.tmp -v >> $LOG
                OPENSSLCONF="${OPENSSLMAILCONF}.tmp"
                ALTOPT=email
            else
                cp $OPENSSLCONF ${OPENSSLCONF}.tmp
                OPENSSLCONF="${OPENSSLCONF}.tmp"
                ALTOPT=DNS
            fi
            OPENSSL_CONF=$OPENSSLCONF
            export OPENSSL_CONF

            echo "Using settings from >$OPENSSLCONF<" >> $LOG

            # some checks and default options 
            if [ -z "$MYCN" ]||[ -z "$CAPEM" ]||[ -z "$CACERT" ];then
                echo && F_ECHOLOG "ERROR: ALL of > -f|F AND -c|C AND -i|I < are required in this mode!" && echo && F_HELP
                exit 2
            else
                # some basic checks and defaults
                [ -z "$BITS" ]&& BITS="${DEFCERTBITS}"
                [ -z "$PKEY" ]&& PKEY="${NEWCRTDIR}/${MYCN}.pem"
                [ ! -f "$CAPEM" ]&& F_ECHOLOG "\nERROR: CAPEM file <$CAPEM> does not exist! Try again or run:\n    $> $0 -m CA -F your-new-root-CA\n  This will create a new ROOT-CA which then can be used in sign mode as '-c'.\n" && F_HELP_SIGN && exit 2
                [ -z "$CDAYS" ]&& F_ECHOLOG "Using default amount of days for signing ($DEFCERTDAYS days)" && CDAYS=$DEFCERTDAYS
                [ -z "$CACHAIN" ]&& CACHAIN="$CACERT"
                [ -z "$SIGNENC" ]&& F_ECHOLOG "Using default sign encryption hash ($DEFSIGNENC)" && SIGNENC=$DEFSIGNENC
                F_COMMONCHKS
            fi

            #preparing some openssl stuff
            CNFCAF=${CAPEM##*/}
            CNFCA=${CNFCAF%\.pem}
            INDEX=${INDEX}_$CNFCA
            SERIAL=${SERIAL}_$CNFCA
            [ ! -f $INDEX ]&& >$INDEX
            [ ! -f $SERIAL ]&& echo "01" >$SERIAL
            # build the correct filenames for CA specific files
            sed -i "s/MCCINECA/$CNFCA/g" $OPENSSLCONF

            # starting the magic 
            if [ ! -f "${PKEY}" ];then
                echo "##########################################################"
                echo "# Creating private key:"
                echo
                OPENSSL_CONF=$OPENSSLCONF openssl genrsa -out ${PKEY} $BITS 2>&1 >>$LOG
                [ $? -ne 0 ]&& F_ECHOLOG "ERROR: While creating private key. ABORTED!" && exit 2
            else
                echo "skipping private key generation - using existing one instead."
            fi

            # preparing the special openssl conf
            # replace default common name with the main one
            sed -i "s/MCCINECN/$MYCN/g" $OPENSSLCONF
           # sed -i "/\[alt_names\]/ a\
#${ALTOPT}.1=$MYCN" $OPENSSLCONF
            
            # set counters
            iCNT=1
            dCNT=2

            # add all the alternative names/ips
            if [ "$ALTOPT" == "email" ];then
                for ALTN in $(echo "$ALLCN" |tr "," " ");do
                    F_MAILCHK "$ALTN"
                    if [ $? -eq 0 ];then
                        echo "<$ALTN> seems to be a valid Email address" >> $LOG
                        sed -i "/\[alt_names\]/ a\
${ALTOPT}.${iCNT}=$ALTN" $OPENSSLCONF && ((iCNT ++))
                    else
                        echo "<$ALTN> seems to be NOT a valid Email address" >> $LOG
                        echo "ABORTED because of possible invalid Email <$ALTN>"
                        exit 2
                    fi
                done
            else
                for ALTN in $(echo "$ALLCN" |tr "," " ");do
                    F_IPCHK "$ALTN"
                    if [ $? -eq 0 ];then
                        echo "<$ALTN> seems to be a valid IP" >> $LOG
                        sed -i "/\[alt_names\]/ a\
    IP.${iCNT}=$ALTN" $OPENSSLCONF && ((iCNT ++))
                    else
                        echo "<$ALTN> seems to be NOT a valid IP therefore we handle it like DNS" >> $LOG
                        sed -i "/\[alt_names\]/ a\
    ${ALTOPT}.${dCNT}=$ALTN" $OPENSSLCONF && ((dCNT ++))
                    fi
                done
            fi
            echo "##########################################################"
            echo "# Creating a request based on that private key:"
            echo
            openssl req -days $CDAYS -new -key ${PKEY} -out ${NEWCRTDIR}/${MYCN}_${CDAYS}-days.req.txt -config $OPENSSLCONF 2>&1 >>$LOG
            [ $? -ne 0 ]&& F_ECHOLOG "ERROR: While creating cert request. ABORTED!" && exit 2

            echo "##########################################################"
            echo "# Self-sign the request and create the wanted cert:"
            echo
	    # the sign process depends on the option choosen
#	    if [ $ALTOPT == "DNS" ];then
#		
#	    else 
            	echo "openssl ca -extensions v3_req -keyfile ${CAPEM} -policy policy_anything -cert $CACERT -days $CDAYS -config $OPENSSLCONF -out ${NEWCRTDIR}/${MYCN}_${CDAYS}-days.crt -infiles ${NEWCRTDIR}/${MYCN}_${CDAYS}-days.req.txt"
            	openssl ca -extensions v3_req -keyfile ${CAPEM} -policy policy_anything -cert $CACERT -days $CDAYS -config $OPENSSLCONF -out ${NEWCRTDIR}/${MYCN}_${CDAYS}-days.crt -infiles ${NEWCRTDIR}/${MYCN}_${CDAYS}-days.req.txt
#	    fi
            [ $? -ne 0 ]&& F_ECHOLOG "ERROR: While signing cert request. ABORTED!" && exit 2
 
            echo "##########################################################"
            echo "# Your certificate can be displayed with:"
            echo "$> openssl x509 -text -in ${NEWCRTDIR}/${MYCN}_${CDAYS}-days.crt"
            openssl x509 -text -in ${NEWCRTDIR}/${MYCN}_${CDAYS}-days.crt
            echo "##########################################################"
            F_ECHOLOG "# Your certificate HASH value (if needed):"
            echo
            CHASH=$(openssl x509 -noout -hash -in ${NEWCRTDIR}/${MYCN}_${CDAYS}-days.crt)
            F_ECHOLOG "$CHASH"
            ln -sf ${NEWCRTDIR}/${MYCN}_${CDAYS}-days.crt ${NEWCRTDIR}/$CHASH && F_ECHOLOG "Created hash link for the certificate for your convenience.."
            echo "##########################################################"

            if [ "$ALTOPT" == "email" ];then
                echo "##########################################################"
                echo "# Creating S/MIME certificate:"
                echo 
                openssl pkcs12 -export -in ${NEWCRTDIR}/${MYCN}_${CDAYS}-days.crt -chain -CAfile ${CACHAIN} -inkey ${PKEY} -out ${NEWCRTDIR}/${MYCN}_${CDAYS}-days.p12
                echo "  Done! Get it here: ${NEWCRTDIR}/${MYCN}_${CDAYS}-days.p12"
                echo "##########################################################"
            else
                echo "##########################################################"
                echo "# Creating chain..."
                cat ${NEWCRTDIR}/${MYCN}_${CDAYS}-days.crt ${CACHAIN} > ${NEWCRTDIR}/${MYCN}_${CDAYS}-days_fullCAchain.crt
                echo "  Done! Get your full cert here: ${NEWCRTDIR}/${MYCN}_${CDAYS}-days_fullCAchain.crt"
                echo "##########################################################"
            fi
            echo
            echo "Congrats your certificate is ready to use now!"
            echo "  Private Key: $PKEY" 
            echo "  Certificate: ${MYCN}_${CDAYS}-days.crt"
            echo "  Cert+Chain: ${NEWCRTDIR}/${MYCN}_${CDAYS}-days_fullCAchain.crt"
            echo
        ;;
        req|csr) F_ECHOLOG "Running in >CSR only< mode." ; MODE=CSR
            ###################################################################################
            ###                                                                             ###
            ### Certificate request only mode                                                       ###
            ###                                                                             ###
            ###################################################################################

            # we do not want to modify the template openssl config so we duplicate it first
            # and we do that depending on the signing mode
            if [ ! -z "$SIGNMODE" ] && [ "$SIGNMODE" == "MAIL" ];then
                cp $OPENSSLMAILCONF ${OPENSSLMAILCONF}.tmp
                OPENSSLCONF="${OPENSSLMAILCONF}.tmp"
                ALTOPT=email
            else
                cp $OPENSSLCONF ${OPENSSLCONF}.tmp
                OPENSSLCONF="${OPENSSLCONF}.tmp"
                ALTOPT=DNS
            fi
            OPENSSL_CONF=$OPENSSLCONF
            export OPENSSL_CONF

            echo "Using settings from >$OPENSSLCONF<" >> $LOG

            # some checks and default options 
            if [ -z "$MYCN" ];then
                echo && F_ECHOLOG "ERROR: > -f|F is required in this mode!" && echo && F_HELP
                exit 2
            else
                # some basic checks and defaults
                [ -z "$BITS" ]&& BITS="${DEFCERTBITS}"
                [ -z "$PKEY" ]&& PKEY="${NEWCRTDIR}/${MYCN}.pem"
                [ -z "$CDAYS" ]&& F_ECHOLOG "Using default amount of days for signing ($DEFCERTDAYS days)" && CDAYS=$DEFCERTDAYS
                [ -z "$SIGNENC" ]&& F_ECHOLOG "Using default sign encryption hash ($DEFSIGNENC)" && SIGNENC=$DEFSIGNENC
                F_COMMONCHKS
            fi

            #preparing some openssl stuff
            CNFCAF=${CAPEM##*/}
            CNFCA=${CNFCAF%\.pem}
            INDEX=${INDEX}_$CNFCA
            SERIAL=${SERIAL}_$CNFCA
            [ ! -f $INDEX ]&& >$INDEX
            [ ! -f $SERIAL ]&& echo "01" >$SERIAL
            # build the correct filenames for CA specific files
            sed -i "s/MCCINECA/$CNFCA/g" $OPENSSLCONF

            # starting the magic 
            if [ ! -f "${PKEY}" ];then
                echo "##########################################################"
                echo "# Creating private key:"
                echo
                openssl genrsa -out ${PKEY} $BITS -config $OPENSSLCONF 2>&1 >>$LOG
                [ $? -ne 0 ]&& F_ECHOLOG "ERROR: While creating private key. ABORTED!" && exit 2
            else
                echo "skipping private key generation - using existing one instead."
            fi

            # preparing the special openssl conf
            # replace default common name with the main one
            sed -i "s/MCCINECN/$MYCN/g" $OPENSSLCONF
          
            # set counters
            iCNT=1
            dCNT=2

            # add all the alternative names/ips
            if [ "$ALTOPT" == "email" ];then
                for ALTN in $(echo "$ALLCN" |tr "," " ");do
                    F_MAILCHK "$ALTN"
                    if [ $? -eq 0 ];then
                        echo "<$ALTN> seems to be a valid Email address" >> $LOG
                        sed -i "/\[alt_names\]/ a\
${ALTOPT}.${iCNT}=$ALTN" $OPENSSLCONF && ((iCNT ++))
                    else
                        echo "<$ALTN> seems to be NOT a valid Email address" >> $LOG
                        echo "ABORTED because of possible invalid Email <$ALTN>"
                        exit 2
                    fi
                done
            else
                for ALTN in $(echo "$ALLCN" |tr "," " ");do
                    F_IPCHK "$ALTN"
                    if [ $? -eq 0 ];then
                        echo "<$ALTN> seems to be a valid IP" >> $LOG
                        sed -i "/\[alt_names\]/ a\
    IP.${iCNT}=$ALTN" $OPENSSLCONF && ((iCNT ++))
                    else
                        echo "<$ALTN> seems to be NOT a valid IP therefore we treat it like DNS" >> $LOG
                        sed -i "/\[alt_names\]/ a\
    ${ALTOPT}.${dCNT}=$ALTN" $OPENSSLCONF && ((dCNT ++))
                    fi
                done
            fi
            echo "##########################################################"
            echo "# Creating a request based on that private key:"
            echo
            openssl req -days $CDAYS -new -key ${PKEY} -out ${NEWCRTDIR}/${MYCN}_${CDAYS}-days.req.txt -$SIGNENC -config $OPENSSLCONF 2>&1 >>$LOG
            if [ $? -ne 0 ];then
                F_ECHOLOG "ERROR: While creating cert request. ABORTED!" && exit 2
            else
                openssl req -text -in ${NEWCRTDIR}/${MYCN}_${CDAYS}-days.req.txt
                echo -e "\n\n"
                echo -e "\tCongrats your certificate request is ready to deploy now!"
                echo -e "\tPrivate Key: $PKEY (keep this protected on your PC)"
                echo -e "\tCertificate request: ${NEWCRTDIR}/${MYCN}_${CDAYS}-days.req.txt"
            fi
        ;;
        *) F_ECHOLOG "Invalid operation mode: <$MODE>"
	       F_HELP
	       exit 2
        ;;
esac


