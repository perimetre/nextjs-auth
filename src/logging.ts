import { yellow } from 'chalk';
import { AuthSettings } from './';

/**
 * @typedef { import("./").AuthEnv } AuthEnv
 */

/**
 * Console.logs given output but appending a prefix
 *
 * @param {() => Promise<AuthEnv>} getEnv An async function used to fetch the environment for the service
 * @param {any[]} data The data that will be logged
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const debug = async (getEnv: AuthSettings['authEnv'], ...data: any[]): Promise<void> => {
  try {
    if ((await getEnv()).DEBUG) {
      console.log(yellow('[nextjs-auth] '), ...data);
    }
  } catch {
    // Do nothing
  }
};

const logging = {
  debug
};

export default logging;
