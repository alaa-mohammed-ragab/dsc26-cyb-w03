# AI usage: dsc26-cyb-w03

## Tools

I used ChatGPT to understand the task requirements, review the three modules, and help implement upload validation, document authorization, and password storage. I also used it to understand the test results and debug implementation issues. I ran the public tests locally using pytest.

## What AI got wrong

During the implementation, I initially encountered a test collection error because I ran pytest from the outer project folder instead of the inner project folder. The import error showed that Python could not find `bayyina_guard`. I corrected the working directory and reran the tests successfully.

## In my own words

<!-- One or two sentences each, written without AI. -->

1. Why does `get_document` return 404 rather than 403 when a client asks for another client's contract?
Because returning 404 hides the existence of the document from unauthorized clients. This prevents attackers from discovering contracts that belong to other clients.

2. Why must `verify_password` refuse a stored hash that is shorter than 32 bytes, even though the prefix matches?
Because a valid scrypt hash must be exactly 32 bytes. A shorter hash is incomplete or malformed, so it must be rejected to prevent accepting invalid password data.