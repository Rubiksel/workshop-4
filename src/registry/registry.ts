import bodyParser from "body-parser";
import express, { Request, Response, response } from "express";
import { REGISTRY_PORT } from "../config";

export type Node = { nodeId: number; pubKey: string };

export type RegisterNodeBody = {
  nodeId: number;
  pubKey: string;
};

export type GetNodeRegistryBody = {
  nodes: Node[];
};

let getNodeRegistryBody:GetNodeRegistryBody={nodes:[]};

export async function launchRegistry() {
  const _registry = express();
  _registry.use(express.json());
  _registry.use(bodyParser.json());
  _registry.get("/status",(req:Request,res:Response)=>{
    res.status(200).send("live");
  });
  _registry.post("/registerNode",(req,res)=>{
    const {nodeId,pubKey}=req.body;
    if (getNodeRegistryBody.nodes.some(n=>n.nodeId===nodeId||n.pubKey===pubKey)) {
      return res.send("Node or public key registered already")
    }
    else {
      getNodeRegistryBody.nodes.push({nodeId,pubKey});
      return res.send("Node registered successfully");
    }
  });

  _registry.get("/getNodeRegistry",(req,res)=>{
    res.json(getNodeRegistryBody);
  });

  _registry.get("/status",(req,res)=>{
    res.send("live");
  });


  const server = _registry.listen(REGISTRY_PORT, () => {
    console.log("registry is listening on port ${REGISTRY_PORT}");
  });

  return server;
}
