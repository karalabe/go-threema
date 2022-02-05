# Threema messaging from Go

This is a [Threema](https://threema.ch/en) bot library written in Go. It uses personal - properly licensed - Threema accounts to send and receive messages.

This library will ***never*** have feature parity with the Threema wire protocol as the goal is personal use (notifications, alerts, commands). If you wish to send Threema messages in production settings with quality of service assurances, please use the [Threema Gateway](https://gateway.threema.ch/en).

*Disclaimer: This library is completely unrelated to the Threema company and project. It may break at any point in time if the protocol changes and there might be no update coming to fix it. Only use in settings where this risk is acceptable.*

## Threema license and account

This project uses personal Threema accounts. It is forbidden to use the same personal account on multiple devices, but running a personal bot with its own dedicated license is *tolerated* (don't blame me if they terminate your license/account due to abuse).

To obtain a dedicated license for your bot, go to the [Threema Shop](https://shop.threema.ch/) and buy a license key for *Threema for Android*. You should get a key in the form of `XXXXX-XXXXX`. This is not yet a Threema account, just a key allowing you to *create* a Threema account on their servers.

Creating the Threema account has its own funky REST workflow against the Threema API servers. The authorization and registration API is not public. Although we could implement the flow in this library, it's asking for trouble wrt compatibility issues long term.

We're going to side track this issue by requesting you to install the [standalone Threema for Android](https://shop.threema.ch/download) either into an extra phone or an Android emulator. Through the app, you will be able to complete the signup workflow no matter how the APIs evolve in the coming years. After completing the signup, you can [export](https://threema.ch/en/faq/idexport2) your live identity.

You should end up with an encrypted backup key consisting of 20x4 characters in the shape of `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX` and your chosen password. You will need both to use this library.

## Threema user directory service

When you attempt to contact an unknown user through Threema (via their 8 character ID) - or when you yourself are contacted by an unknown user - communication is not possible until the public key associated with the account is retrieved. This does not happen within the Threema chat protocol, rather relies on a REST API operated by Threema.

Similarly to how this library avoided implementing the registration workflow, public key retrievals are also delegated to the user. This ensures that the library itself - focusing on communication through the Threema chat protocol - will not break due to some REST API change, and will continue to function even if the directory service is offline.

To retrieve the public key of a user identified by their 8 character Threema ID, make an HTTP `GET` request to `https://api.threema.ch/identity/XXXXXXXX`. The response will be a JSON struct containing, among other fields, `{"publicKey": "..."}`. This is the base64 encoded 32byte public key you'll need to contact a specific user.

## How to use this library

Before you can start messaging, you'll need to load your exported backup key into a `threema.Identity`.

```go
// We assume you already have an exported identity (don't get your hopes up,
// this is a fake identity).
var (
    backup   = "A4G3-BF25-JEN4-EA7Q-XSMG-AIYL-A2W6-CCTW-VYGW-HT3L-KVA7-TTG7-VF2G-RHMY-YB5I-ER7S-WQMU-XF4Y-PZLU-XJFN"
    password = "1337speak"
)
// Loading an exported identity is as simple as providing the exported backup
// string and the password it was encrypted with.
id, err := threema.Identify(backup, password)
if err != nil {
    panic(err)
}
fmt.Printf("Loaded Threema identity: %s\n", id.Self())
```

This identity is enough to establish a connection to the Threema chat servers, a `threema.Connection`.

```go
// We assume you already loaded an exported identity though this library, as
// well as a handler that reacts to events. Mode on this later.
var (
    id      *threema.Identity
    handler *threema.Handler
)
// With a real identity and an event handler (you can use nil for a dry run),
// it's already enough to authenticate into the Threema network.
conn, err := threema.Connect(id, handler)
if err != nil {
    panic(err)
}
defer conn.Close()

fmt.Printf("Connected to the Threema network\n")
```

Before sending the first message, you'll need to create a `threema.Hanler` to react to inbound events. The handler is constructed as an *"abstract interface"* so you can provide only the methods you're interested in and drop everything else onto the floor.

```go
// There are various events that a user might want to react to. These are
// most commonly messages received from others, but there are also a few
// Threema protocol events too.
handler := &threema.Handler{
    Message: func(from string, nick string, when time.Time, msg string) {
        fmt.Printf("%v] %s(%s): %s\n", when, from, nick, msg)
    },
}
fmt.Printf("Handler methods implemented: %+v\n", handler)
```

With all the setup in place, we can send - and receive - our very first Threema message from Go!

```go
// We assume you already loaded an exported identity though this library, as
// well as established a live connection to the Threema servers.
var (
    id   *threema.Identity
    conn *threema.Connection
)
// Sending a message will block until it is delivered to the Threema servers
// and it is acknowledged by it (i.e. no data loss). There is no waiting for
// the remote side to receive nor read it!
if err := conn.SendText(id.Self(), "Hello Threema!"); err != nil {
    panic(err)
}
fmt.Printf("We've just sent out first message!\n")
```

Before you can send (or receive) messages from a different user, you need to know their Threema ID and public key. Although it is possible to seamlessly retrieve the key from Threema's directory service, this library will not do it for you, sorry.

```go
// We assume you already loaded an exported identity though this library, as
// well as retrieved a known user's base64 encoded public key from Threema's
// user directory service.
var (
    id *threema.Identity

    friend = "DEADBEEF"
    pubkey = "1qEnvgAm59YN0VUQqjOWHF3TymgIcIdMDpH7p1GajQU="
)
// Add the friend's key mapped to their Threema ID.
if err := id.Trust(friend, pubkey); err != nil {
    panic(err)
}
fmt.Printf("We've just trusted %s to message with\n", friend)
```

## Contributing

*Don't.*

I do not have the capacity to maintain a project that tracks a constantly evolving product (Threema). The more feature parity this library has with the protocol, the higher the probability of breakages. 

My goal is to use a very limited subset of features for personal notifications and maybe some automations. I may in the future add more things I use, but I will definitely not add anything I don't.

Last but not least, Threema made an amazing product and I don't want this library to compete with - or be to the detriment of - their commercial offerings. I feel that running a fully licenced personal bot with very limited traffic is within the limits of good faith; and I don't want to push the envelope too far.

## License

3-Clause BSD