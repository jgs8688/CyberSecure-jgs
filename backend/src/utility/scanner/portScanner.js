import net from 'net';

export const scanOpenPorts = async (url) => {
  const host = new URL(url).hostname;
const portsToCheck = [
  21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 123, 135, 137, 138, 139,
  143, 161, 162, 389, 443, 445, 465, 514, 587, 993, 995,
  1433, 1521, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200
];
  const openPorts = [];

  const checkPort = (port) =>
    // Check if the port is open by attempting to connect
    // to it and resolving the promise based on the result
    console.log(`Checking port ${port} on ${host}`) ||
    new Promise((resolve) => {
      const socket = new net.Socket();
      socket.setTimeout(1000);
      socket.once('connect', () => {
        openPorts.push(port);
        socket.destroy();
        resolve();
      });
      socket.once('timeout', () => {
        socket.destroy();
        resolve();
      });
      socket.once('error', () => {
        resolve();
      });
      socket.connect(port, host);
    });

  await Promise.all(portsToCheck.map(checkPort));
  return { found: openPorts.length > 0, openPorts };
};
