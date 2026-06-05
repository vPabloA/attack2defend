declare module 'react-force-graph-2d' {
  import type { ComponentType } from 'react';

  type ForceGraph2DProps = {
    graphData: { nodes: unknown[]; links: unknown[] };
    width?: number;
    height?: number;
    nodeLabel?: (node: unknown) => string;
    linkLabel?: (link: unknown) => string;
    nodeVal?: (node: unknown) => number;
    nodeCanvasObject?: (node: unknown, ctx: CanvasRenderingContext2D, globalScale: number) => void;
    linkDirectionalArrowLength?: number;
    linkDirectionalArrowRelPos?: number;
    linkDirectionalParticles?: number;
    linkDirectionalParticleWidth?: number;
    onNodeClick?: (node: unknown) => void;
    onNodeHover?: (node: unknown | null) => void;
    onLinkHover?: (link: unknown | null) => void;
  };

  const ForceGraph2D: ComponentType<ForceGraph2DProps>;
  export default ForceGraph2D;
}
