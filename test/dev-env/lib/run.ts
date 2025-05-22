import { TestNetwork } from "./network.js";

export async function run() {
  console.log("Starting network...");
  const network = await TestNetwork.create({});
  console.log("Network started", network);
}

run();
