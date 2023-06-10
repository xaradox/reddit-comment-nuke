import sys
import argparse
import json
import praw
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from base64 import b64encode, b64decode

def auth_user(user_client_id, user_client_secret, user_username, user_password):
    reddit = praw.Reddit(
        client_id=user_client_id,
        client_secret=user_client_secret,
        user_agent='reddit-comment-nuke-'+user_username,
        username=user_username,
        password=user_password
    )
    reddit.validate_on_submit = True

    user = reddit.user.me()
    if user == user_username:
        return user
    else:
        return None

def get_comments(user):
    return user.comments.new(limit=None)

def save_comments(comments):
    from datetime import datetime

    with open('comments.json','w',encoding='utf-8') as f_comments:
        data = []
        for comment in comments:
            comment_dict = {"comment_id" : comment.id,
                            "date" : datetime.utcfromtimestamp(comment.created_utc).strftime('%Y/%m/%d'),
                            "subreddit" : comment.subreddit.display_name,
                            "comment_body" : comment.body}
            data.append(comment_dict)
        json.dump(data, f_comments, indent=4, ensure_ascii=False)

def encrypt_text(text, key):
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(key).encrypt(nonce, text, b"")

def decrypt_text(text, key):
    return AESGCM(key).decrypt(text[:12], text[12:], b"")

# All comments are edited according to this string
replace_with = """
*This comment has been edited in protest to reddit's API policy changes, their treatment of developers of 3rd party apps, and their response to community backlash.*  
  
&nbsp;  
[Details of the end of the Apollo app](https://old.reddit.com/r/apolloapp/comments/144f6xm/apollo_will_close_down_on_june_30th_reddits/)  

---
[Why this is important](https://i.imgur.com/E7jSWf1.jpg)  

---
[An open response to spez's AMA](https://old.reddit.com/r/ModCoord/comments/145l7wp/todays_ama_with_spez_did_nothing_to_alleviate/)  

---
[spez AMA and notable replies](https://old.reddit.com/r/SubredditDrama/comments/145beas/spez_ama_discussion_thread/)

&nbsp;  
Fuck spez. I edited this comment before he could.  
Comment ID={} Ciphertext:  
>!{}!<
"""

def main(self):
    # Parse command-line args
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--save-locally',action='store_true',
                        help='Flag to save comments locally')
    group.add_argument('--restore-comments',action='store_true',
                        help='Flag to restore comments to their original state')
    args = vars(parser.parse_args())

    # Load user credentials
    with open('config/credentials.json','r',encoding='utf-8') as f_credentials:
        credentials = json.load(f_credentials)

    # Generate a secret key if one does not exist
    if credentials['encryption_key'] == "":
        with open('config/credentials.json','w',encoding='utf-8') as f_credentials:
            credentials['encryption_key'] = b64encode(secrets.token_bytes(32)).decode()
            json.dump(credentials, f_credentials, indent=4)

    # Users AES-GCM secret key 
    key = credentials['encryption_key']

    # Authenticate user
    user = auth_user(
        credentials['client_id'],
        credentials['client_secret'],
        credentials['username'],
        credentials['password'],
    )

    if user == None:
        raise Exception('Error: Failed to authenticate user')

    # Restore comments to their original content
    # Could attempt to restore from local copy if it exists?
    # Otherwise extract ciphertext from user comments and decrypt
    if args['restore_comments']:
        raise NotImplementedError()

    comments = get_comments(user)

    if args['save_locally']:
        save_comments(comments)

    for comment in comments:
        if ('ID=' + comment.id) not in comment.body:
            # Encrypt the comment body with the user key
            encrypted_comment = encrypt_text(comment.body.encode(), key)
            # Fix encoding of comment ciphertext
            encrypted_comment = b64encode(encrypted_comment).decode()
            # Edit the comment according to 'replace_with' and insert ciphertext 
            comment.edit(replace_with.format(comment.id, encrypted_comment))

if __name__ == '__main__':
    main(sys.argv[1:])