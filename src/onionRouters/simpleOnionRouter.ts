import bodyParser from "body-parser";
import express from "express";
import { BASE_ONION_ROUTER_PORT } from "../config";
import { exportPrvKey, exportPubKey, generateRsaKeyPair, importPrvKey, rsaDecrypt } from "../crypto";
import { webcrypto } from "crypto";

export async function simpleOnionRouter(nodeId: number) {
  const onionRouter = express();
  onionRouter.use(express.json());
  onionRouter.use(bodyParser.json());
  var lastReceivedEncryptedMessage:string|null=null;
  var lastReceivedDecryptedMessage:string|null=null;
  var lastMessageDestination:number|null=null;
  const {publicKey,privateKey}=await generateRsaKeyPair();
  const privateKeyBase64=await exportPrvKey(privateKey);
  const publicKeyBase64=await exportPubKey(publicKey);
  onionRouter.get("/status",(req,res)=>{
    res.send("live");
  });

  onionRouter.get("/getLastReceivedEncryptedMessage",(req,res)=>{
    res.json({result:lastReceivedEncryptedMessage});
  });

  onionRouter.get("/getLastReceivedDecryptedMessage",(req,res)=>{
    res.json({result:lastReceivedDecryptedMessage});
  });

  onionRouter.get("/getLastMessageDestination",(req,res)=>{
    res.json({result:lastMessageDestination})
  });

  onionRouter.get("/getPrivateKey",(req,res)=>{
    res.json({result:privateKeyBase64});
  });

  onionRouter.post("/message",async(req,res)=>{
    const layer=req.body.message;
    const encryptedKey=layer.slice(0,344);
    const Key=privateKeyBase64 ? await rsaDecrypt(encryptedKey, await importPrvKey(privateKeyBase64)):null;
    const encryptedMessage=layer.slice(344);
    const message=Key ? await rsaDecrypt(Key,encryptedMessage):null;
    lastReceivedEncryptedMessage=layer;
    lastReceivedDecryptedMessage=message ? message.slice(10):null;
    lastMessageDestination=message ? parseInt(message.slice(0,10),10):null;
    await fetch("http://localhost:${lastMessageDestination}/message",{
      method:"POST",
      body:JSON.stringify({message:lastReceivedDecryptedMessage}),
      headers:{"Content-type":"application/json"},
    });
    res.send("success");
  });

  const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
    console.log(
      `Onion router ${nodeId} is listening on port ${
        BASE_ONION_ROUTER_PORT + nodeId
      }`
    );
  });

  return server;
}
