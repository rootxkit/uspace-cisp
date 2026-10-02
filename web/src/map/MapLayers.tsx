"use client";

import { useMemo } from "react";
import { RestrictionLayer, ZoneLayer } from "@rootxkit/uspace-ui/layers";
import { MapControls, useBBoxSubscription, type BBox, type LayerToggle } from "@rootxkit/uspace-ui/map";
import type { MapDataset } from "../public/banner";
import type { MapFeature } from "./adapt";

/**
 * How the visible box becomes the read's bbox (spec 05 §5): padded by a
 * quarter of the view, widened to a 0.05° grid so a small pan reads
 * nothing again, and read 300 ms after the map settles. Display-only.
 */
export const BBOX_MARGIN_FRACTION = 0.25;
export const BBOX_QUANTIZE_DEG = 0.05;
export const BBOX_DEBOUNCE_MS = 300;

/** Calls `onChange` with the padded, quantised bbox of the enclosing MapView. */
export function BBoxWatcher({ onChange }: { onChange(b: BBox): void }) {
  useBBoxSubscription({
    marginFraction: BBOX_MARGIN_FRACTION,
    quantizeDeg: BBOX_QUANTIZE_DEG,
    debounceMs: BBOX_DEBOUNCE_MS,
    onChange,
  });
  return null;
}

/**
 * The three layers in the kit's symbology: zones and U-space airspace by
 * zone type (two ZoneLayers, so each toggles on its own), restrictions by
 * type and state; the kit's controls with the layer toggles.
 */
export function MapLayers(props: {
  features: Record<MapDataset, MapFeature[]>;
  visible: Record<MapDataset, boolean>;
  onVisible(d: MapDataset, v: boolean): void;
  selectedId: string | null;
  onSelect(id: string): void;
}) {
  const { features, visible, onVisible, selectedId, onSelect } = props;
  const zones = useMemo(() => features.zones.map((f) => f.view), [features.zones]);
  const uspace = useMemo(() => features.uspace_airspace.map((f) => f.view), [features.uspace_airspace]);
  const restrictions = useMemo(() => features.restrictions.map((f) => f.view), [features.restrictions]);
  const toggles: LayerToggle[] = (["zones", "uspace_airspace", "restrictions"] as const).map((d) => ({
    id: d,
    labelKey: `cisp.dataset.${d}`,
    visible: visible[d],
    onChange: (v: boolean) => onVisible(d, v),
  }));
  return (
    <>
      <ZoneLayer id="cisp-uspace" zones={uspace} visible={visible.uspace_airspace} selectedId={selectedId} onSelect={onSelect} />
      <ZoneLayer id="cisp-zones" zones={zones} visible={visible.zones} selectedId={selectedId} onSelect={onSelect} />
      <RestrictionLayer id="cisp-restrictions" restrictions={restrictions} visible={visible.restrictions} onSelect={onSelect} />
      <MapControls layers={toggles} />
    </>
  );
}
