#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies 
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Modify msDS-GroupMSAMembership security descriptor of a distinguished name
#
# Author:
#   janne808 (janne808@radiofreerobotron.net)
#
# Reference for:
#   LDAP
#

from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_credentials
from impacket.dcerpc.v5 import samr, epm, transport
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech

from impacket.ldap import ldaptypes
from impacket.ldap import ldap, ldapasn1

import os
import sys
import ssl
import ldap3
import argparse
import logging
from binascii import unhexlify

def LDAP3KerberosLogin(connection, target, user, password, domain='', lmhash='', nthash='', aesKey='', kdcHost=None, TGT=None, TGS=None, useCache=True):
    from pyasn1.codec.ber import encoder, decoder
    from pyasn1.type.univ import noValue
    """
    logins into the target system explicitly using Kerberos. Hashes are used if RC4_HMAC is supported.

    :param string target: target
    :param string user: username
    :param string password: password for the user
    :param string domain: domain where the account is valid for (required)
    :param string lmhash: LMHASH used to authenticate using hashes (password is not used)
    :param string nthash: NTHASH used to authenticate using hashes (password is not used)
    :param string aesKey: aes256-cts-hmac-sha1-96 or aes128-cts-hmac-sha1-96 used for Kerberos authentication
    :param string kdcHost: hostname or IP Address for the KDC. If None, the domain will be used (it needs to resolve tho)
    :param struct TGT: If there's a TGT available, send the structure here and it will be used
    :param struct TGS: same for TGS. See smb3.py for the format
    :param bool useCache: whether or not we should use the ccache for credentials lookup. If TGT or TGS are specified this is False

    :return: True, raises an Exception if error.
    """

    if lmhash != '' or nthash != '':
        if len(lmhash) % 2:
            lmhash = '0' + lmhash
        if len(nthash) % 2:
            nthash = '0' + nthash
        try:  # just in case they were converted already
            lmhash = unhexlify(lmhash)
            nthash = unhexlify(nthash)
        except TypeError:
            pass

    # Importing down here so pyasn1 is not required if kerberos is not used.
    from impacket.krb5.ccache import CCache
    from impacket.krb5.asn1 import AP_REQ, Authenticator, TGS_REP, seq_set
    from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
    from impacket.krb5 import constants
    from impacket.krb5.types import Principal, KerberosTime, Ticket
    import datetime

    if TGT is not None or TGS is not None:
        useCache = False

    targetName = 'ldap/%s' % target

    if useCache:
        domain, user, TGT, TGS = CCache.parseFile(domain, user, targetName)

    # First of all, we need to get a TGT for the user
    userName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    if TGT is None:
        if TGS is None:
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, password, domain, lmhash, nthash,
                                                                        aesKey, kdcHost)
    else:
        tgt = TGT['KDC_REP']
        cipher = TGT['cipher']
        sessionKey = TGT['sessionKey']

    if TGS is None:
        serverName = Principal(targetName, type=constants.PrincipalNameType.NT_SRV_INST.value)
        tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, domain, kdcHost, tgt, cipher,
                                                                    sessionKey)
    else:
        tgs = TGS['KDC_REP']
        cipher = TGS['cipher']
        sessionKey = TGS['sessionKey']

        # Let's build a NegTokenInit with a Kerberos REQ_AP

    blob = SPNEGO_NegTokenInit()

    # Kerberos
    blob['MechTypes'] = [TypesMech['MS KRB5 - Microsoft Kerberos 5']]

    # Let's extract the ticket from the TGS
    tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
    ticket = Ticket()
    ticket.from_asn1(tgs['ticket'])

    # Now let's build the AP_REQ
    apReq = AP_REQ()
    apReq['pvno'] = 5
    apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

    opts = []
    apReq['ap-options'] = constants.encodeFlags(opts)
    seq_set(apReq, 'ticket', ticket.to_asn1)

    authenticator = Authenticator()
    authenticator['authenticator-vno'] = 5
    authenticator['crealm'] = domain
    seq_set(authenticator, 'cname', userName.components_to_asn1)
    now = datetime.datetime.now(datetime.timezone.utc)

    authenticator['cusec'] = now.microsecond
    authenticator['ctime'] = KerberosTime.to_asn1(now)

    encodedAuthenticator = encoder.encode(authenticator)

    # Key Usage 11
    # AP-REQ Authenticator (includes application authenticator
    # subkey), encrypted with the application session key
    # (Section 5.5.1)
    encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 11, encodedAuthenticator, None)

    apReq['authenticator'] = noValue
    apReq['authenticator']['etype'] = cipher.enctype
    apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

    blob['MechToken'] = encoder.encode(apReq)

    request = ldap3.operation.bind.bind_operation(connection.version, ldap3.SASL, user, None, 'GSS-SPNEGO', blob.getData())

    # Done with the Kerberos saga, now let's get into LDAP
    # try to open connection if closed
    if connection.closed:
        connection.open(read_server_info=False)

    connection.sasl_in_progress = True
    response = connection.post_send_single_response(connection.send('bindRequest', request, None))
    connection.sasl_in_progress = False
    if response[0]['result'] != 0:
        raise Exception(response)

    connection.bound = True

    return True

if __name__ == '__main__':
    logger.init()
    print((version.BANNER))
    
    parser = argparse.ArgumentParser(add_help = True, description = "Modify msDS-GroupMSAMembership security descriptor of a distinguished name")

    if sys.version_info.major == 2 and sys.version_info.minor == 7 and sys.version_info.micro < 16: #workaround for https://bugs.python.org/issue11874
        parser.add_argument('account', action='store', help='[domain/]username[:password] Account used to authenticate to DC.')
    else:
        parser.add_argument('account', action='store', metavar='[domain/]username[:password]', help='Account used to authenticate to DC.')

    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    
    group = parser.add_argument_group('LDAP')
    
    group.add_argument('-sid', action='store', metavar='SID', help='SID for msDS-GroupMSAMembership security descriptor')
    group.add_argument('-dn', action='store', metavar='DN', help='Distinguished Name of the account containing the msDS-GroupMSAMembership attribute to modify')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                                                       '(KRB5CCNAME) based on account parameters. If valid credentials '
                                                       'cannot be found, it will use the ones specified in the command '
                                                       'line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')
    group.add_argument('-dc-host', action='store',metavar = "hostname",  help='Hostname of the domain controller to use. '
                                                                              'If ommited, the domain part (FQDN) '
                                                                              'specified in the account parameter will be used')
    group.add_argument('-dc-ip', action='store',metavar = "ip",  help='IP of the domain controller to use. '
                                                                      'Useful if you can\'t translate the FQDN.'
                                                                      'specified in the account parameter will be used')
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    # handle debugging
    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)    
    
    # LDAP account details
    domain, username, password = parse_credentials(options.account)

    try:
        if domain is None or domain == '':
            logging.critical('Domain should be specified!')
            sys.exit(1)

        if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
            from getpass import getpass
            password = getpass("Password:")

        if options.dc_ip is not None:
            kdcHost = options.dc_ip
            connectTo = options.dc_ip

        if options.dc_host is None:
            raise ValueError("Kerberos auth requires DNS name of the target DC. Use -dc-host.")
        else:
            kdcHost = options.dc_host

        if options.hashes is not None:
            lmhash, nthash = options.hashes.split(':')
        else:
            lmhash = ''
            nthash = ''

        # combine domain and username for NTLM authentication
        user = '%s\\%s' % (domain, username)
        
        tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2, ciphers='ALL:@SECLEVEL=0')

        ldapServer = ldap3.Server(connectTo, use_ssl=True, get_info=ldap3.ALL, tls=tls)
   
        # handle credentials
        if options.k:
            ldapConn = ldap3.Connection(ldapServer)
            LDAP3KerberosLogin(ldapConn, kdcHost, username, password, domain, lmhash, nthash, options.aesKey, kdcHost, None)
        elif options.hashes is not None:
            ldapConn = ldap3.Connection(ldapServer, user=user, password=options.hashes, authentication=ldap3.NTLM)
            ldapConn.bind()
        else:
            ldapConn = ldap3.Connection(ldapServer, user=user, password=password, authentication=ldap3.NTLM)
            ldapConn.bind()
            
        # build security descriptor blob
        sid = options.sid
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
        sd['Revision'] = b'\x01'
        sd['Sbz1'] = b'\x00'
        sd['Control'] = 32772
        sd['OwnerSid'] = ldaptypes.LDAP_SID(); sd['OwnerSid'].fromCanonical('S-1-5-18')
        sd['GroupSid'] = b''
        sd['Sacl'] = b''
        acl = ldaptypes.ACL(); acl['AclRevision'] = 4; acl['Sbz1'] = 0; acl['Sbz2'] = 0
        ace = ldaptypes.ACE(); ace['AceType'] = 0; ace['AceFlags'] = 0
        nace = ldaptypes.ACCESS_ALLOWED_ACE(); nace['Mask'] = ldaptypes.ACCESS_MASK()
        nace['Mask']['Mask'] = 983551
        nace['Sid'] = ldaptypes.LDAP_SID(); nace['Sid'].fromCanonical(sid)
        ace['Ace'] = nace
        acl.aces = [ace]; sd['Dacl'] = acl

        # modify DN attribute
        ldapConn.modify(options.dn,
                        {'msDS-GroupMSAMembership': [(ldap3.MODIFY_REPLACE, [sd.getData()])]})

        if ldapConn.result['result'] == 0:
            print('[+] msDS-GroupMSAMembership modified to {sid}'.format(sid=sid))

    except Exception as e:
        if logging.getLogger().level ==logging.DEBUG:
            import traceback
            traceback.print_exc()
        print(str(e))
