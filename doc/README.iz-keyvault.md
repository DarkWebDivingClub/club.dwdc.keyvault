### IZ KeyVault

IZ KeyVault is a pragmatic key generator written in java. It currently runs on Linux but should in theory run on both
Windows and macOS. The idee is to have a system that allows the user to manage his keys in a simple and unified way. The
principal is pretty simple. First you generate a master seed, this one should be saved in /tmp then stored in a very
safe place. Then you use this key to generate a sub-key this is stored in the users home, per default this is
'~/.config/iz-keyvault/'. Then you can create an id, like alice@atlanta.com. From this id you then generate keys for
different protocols. Currently, we support openpgp, ssh and nostr. If you need your key on another computer you simply
move your seed there. The master seed will always be able to regenerate all the keys.

### Why?

In theory public key authentication models should be superior to password base models. But in practice the key
management part turns everything into a mess. As a security expert I have seen the most horrific examples, including ssh
keys that are stored unencrypted in the users home folder that give anybody root access to the build server no questions
asked and no logs provided.

#### Convenience matters

Whether we like it or not, humans, and yes programmers are humans (so far), are creatures of convenience, and they will
bypass any security mechanism that does not make sense or that causes a discomfort. IZ-KeyStore aims to be convenient,
very convenient. If it's not convenient it's not secure.

#### Your keys, your money, your responsibility

IZ-keystore have been designed for a use case where the user is in charge. It deos not they to enforce a security police
that others has deemed to be secure, unlike things like say TMP. If you do stupid thing, bad stuff can happen to you.

### What works today

Today you can create a master-seed, store it in /tmp, save and back up this and the remove it from the device. Then you
can create a sub-seed from this. This seed is stored on the device. From this you can then generate profiles, and after
than keypair for different protocols. These keys can then be exported out into formats that are common for those
protocols.

### What I hope will work tomorrow

#### Roadmap (this that we are currently working on)

* Integrate with "agent" protocols like ssh-agent, gpg-agent so that you don't have to export out the keys.
* Make the system run on more OS:es
* Make the system handle X509.
* Make the system handle BTC.

#### Starmap (long term vision)

* Support a client - keystore model where the keys (and hence the sub-seed) is stored in a secure device like a phone.
  And then you communicate over som sort of generic protocol, like NIP-46.
* Make sure you can use this device to log in, and that login in with this device is the only action you need to
  perform.

### Building

To build the tool simply use mvn

    mvn package

### Usage

#### Create the master seed

This will create the master seed, do this first. We place it in the temp folder. Make sure to save it in a secure place

    iz-keyvault master-seed create --master-seed-file /tmp/master-seed

#### Create the sub seed

This will create the sub seed. This is the seed we will use to create all of your keys.

    iz-keyvault sub-seed create --master-seed-file /tmp/master-seed

#### Create a new profile in your vault

This will create a new profile in your vault

    iz-keyvault identity create --id="alice@atlanta.com" --name="Alice"

#### Create a new ssh-key

This will create a new ssh-key under your profile

    iz-keyvault ssh-keypair create 

#### Export the ssh-key

This will export you key into your .ssh directory (can overwrite files)

    iz-keyvault ssh-keypair export

#### Create a new nostr-key

    iz-keyvault nostr-keypair create

#### Export the nostr-key

     iz-keyvault nostr-keypair export

#### Create a new openpgp-key

     iz-keyvault openpgp-keypair create


#### Export the openpgp-key

    iz-keyvault openpgp-keypair export --password=veryseacret
