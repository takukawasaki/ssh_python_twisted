#!/Users/kawasakitaku/Documents/python-PVM/ln-python2.7/bin/python2.7

from sshserver import SSHDemoRealm, getRSAKeys
from twisted.conch import error
from twisted.conch.ssh import keys, factory
from twisted.cred import checkers, credentials, portal
from twisted.internet import reactor
from twisted.python import failure
from zope.interface import implements
import base64

class PublicKeyCredentialsChecker(object):
    implements(checkers.ICredentialsChecker)
    credentialInterfaces = (credentials.ISSHPrivateKey,)

    def __init__(self, authorizedKeys):
        self.authorizedKeys = authorizedKeys

    def requestAvatarId(self, credentials):
        userKeyString = self.authorizedKeys.get(credentials.username)
        if not userKeyString:
            return failure.Failure(error.ConchError("No such user"))

        # Remove the 'ssh-rsa' type before decoding.
        if credentials.blob != base64.decodestring(
            userKeyString.split(" ")[1]):
            raise failure.failure(
                error.ConchError("I don't recognize that key"))

        if not credentials.signature:
            return failure.Failure(error.ValidPublicKey())

        userKey = keys.Key.fromString(data=userKeyString)
        if userKey.verify(credentials.signature, credentials.sigData):
            return credentials.username
        else:
            print "signature check failed"
            return failure.Failure(
                error.ConchError("Incorrect signature"))

sshFactory = factory.SSHFactory()
sshFactory.portal = portal.Portal(SSHDemoRealm())

# The server's keys.
pubKey, privKey = getRSAKeys()
sshFactory.publicKeys = {"ssh-rsa": pubKey}
sshFactory.privateKeys = {"ssh-rsa": privKey}

# Authorized client keys.
authorizedKeys = {
    "admin":



    }
sshFactory.portal.registerChecker(
    PublicKeyCredentialsChecker(authorizedKeys))

reactor.listenTCP(2222, sshFactory)
reactor.run()
