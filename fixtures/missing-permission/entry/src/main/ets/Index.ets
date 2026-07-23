import { geoLocationManager } from "@kit.LocationKit";

export async function locateOnce() {
  return geoLocationManager.getCurrentLocation();
}
