import logging
import hashlib
import os
import azure.functions as func

from azure.storage.blob import BlobClient

# NEED TO REPLACE EACH TIME A NEW RESOURCE GROUP IS MADE
connection_string = "DefaultEndpointsProtocol=https;AccountName=md5test;AccountKey=XdOG8O7c8VXc42xqxxhr8nmMYo3Ir3TJ8A4BmFhhf+Mpg2hnPk+xu1DtmkV1g/QfWqs+BdoALOX/h/2LOvZVGw==;EndpointSuffix=core.windows.net"
# service = BlobServiceClient.from_connection_string(conn_str=connection_string)

# directory = ""#"/home/site/wwwroot/"

def hash_compute(container, file):
    # https://www.quickprogrammingtips.com/python/how-to-calculate-md5-hash-of-a-file-in-python.html
    md5_hash = hashlib.md5()

    logging.info(f'Downloading file from {container}/{file}')

    blob = BlobClient.from_connection_string(conn_str=connection_string, container_name=container, blob_name=file)
    blob_data = blob.download_blob()

    # with open("./BlockDestination.txt", "wb") as my_blob:
    #     blob_data = blob.download_blob()
    #     blob_data.readinto(my_blob)

    # with open("BlockDestination.txt","rb") as f:
    #     # Read and update hash in chunks of 4K
    #     for byte_block in iter(lambda: blob_data.read(4096),b""):
    #         md5_hash.update(byte_block)
    #     readable_hash = md5_hash.hexdigest()
    
    # return readable_hash

    logging.info(f'Hashing file.')

    md5_hash.update(blob_data.content_as_bytes()) 

    logging.info(f'Hashing done.')

    return md5_hash.hexdigest()


def main(req: func.HttpRequest, msg: func.Out[func.QueueMessage]) -> func.HttpResponse:
#def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    container = req.params.get("container")
    file = req.params.get("file")

    if not (container and file):
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            container = req_body["container"]
            file = req_body["file"]

    if container and file:
        logging.info(f"Path is: {container}/{file}")

        try:
            hash = hash_compute(container, file)
            logging.info(f'Hash is {hash}')

            msg.set(f"{file}:{hash}")
            logging.info(f'Hash written to queue.')

            return func.HttpResponse(f"The MD5 hash of {file} is {hash}")
        except:
            return func.HttpResponse(f"The following file was not found: {file}")
    else:
        return func.HttpResponse(
             f"Either the container {container} wasn't able to be accessed, or the file {file} wasn't able to be accesed in the container.",
             status_code=200
        )
