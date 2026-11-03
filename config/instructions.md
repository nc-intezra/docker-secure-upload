# How to send files across

1. Enter your username. It is recorded with every file you send.
2. Drag files onto the drop area, or choose **Browse** to pick them.
3. Your files keep their names on the other side. Tick **Add the batch ID and my username to file names** only if you want each name to start with the date, your username and a batch number.
4. Select **Upload**. Large files are sent in pieces and resume automatically if the connection drops; keep this page open until every file shows a result.
5. Write down the SHA-256 shown for each file. The receiving side gets the same value in a .sha256 file next to it.

## What happens to your files

- Every file is checked for viruses before it is passed on.
- Files that fail the check are blocked and do not cross. An administrator can review them.
- Very large files (over about 4 GB) cannot be fully scanned. They are passed on and marked as not fully scanned.
- Characters that are not allowed in file names on Windows or Linux (such as ? * : < > | and quotes) are replaced with _. The page shows the new name when this happens.
- If a file with the same name is still waiting to cross, yours waits until it has gone, so nothing is overwritten.
