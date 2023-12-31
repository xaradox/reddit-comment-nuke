# reddit-comment-nuke
Python script to edit personal comment history on reddit.com.  
Created in protest to changes to Reddit's API policy which will kill 3rd party apps.

## Pre-requisites
- Python 3
- [PRAW](https://github.com/praw-dev/praw/tree/master)  
```
pip install praw
```
- [Cryptography](https://pypi.org/project/cryptography/)  
```
pip install cryptography
```
# Warning  
If you want to be able to restore your comments, you **MUST** run the script with the --save-locally flag *first*.  
The functionality to restore from the encrypted comment is not yet implemented, so if you edit your comments without saving them first you won't be able to restore them until it is finished.  

## Usage
- Create a reddit app ([here](https://www.reddit.com/prefs/apps/))  
- `description` and `about url` can be left blank
- `redirect uri` is required (You can use: `http://www.example.com/unused/redirect/uri`)  
  <img src="https://miro.medium.com/v2/resize:fit:720/format:webp/1*7cGAKth1PMrEf2sHcQWPoA.png" width="400"/>
- Note the client ID (`client_id`) and secret token (`client_secret`)
- Clone this repository  
```bash
git clone https://github.com/xaradox/reddit-comment-nuke && cd reddit-comment-nuke
```
- Add client ID, secret token, and reddit user credentials to `config/credentials.json`
- Run the script  
```
py comments_nuke.py [--save-locally | --restore-comments]
```

| Flag                | Description                                                             |
| ------------------- | ----------------------------------------------------------------------- |
| --save-locally      | Flag to save comments locally (`comments.json`) instead of editing them |
| --restore-comments  | Flag to restore comments to their original state. (Currently only capable of restoring from local saves)|
