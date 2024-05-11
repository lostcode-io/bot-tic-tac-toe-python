# Tic-tac-toe sample bot

'Tic-tac-toe' game bot for the LostCode.io website written in pure Python 3.

This is sample bot, the simplest you can do: and will choose his turn absolutely random.

## How to run

Please make sure Python3 is installed on your machine.

To run this bot you need to get the SECRET from the lostcode.io website.
Use it via env variable:

```bash
SECRET=xxxx python3 sample_bot.py --version 0.0.1
```

or via command line argument:

```bash
python3 sample_bot.py --secret xxxx --version 0.0.1
```

You can also specify the port of the game server (default is `8080`):

```bash
python3 sample_bot.py --secret xxxx --version 0.0.1 --port 8081
```
