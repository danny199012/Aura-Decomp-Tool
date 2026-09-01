import { useEffect, useRef } from 'react';
import * as d3 from 'd3';
import type { GraphEdge, GraphNode, InteractiveCallGraph } from '../../types';

export interface ForceGraphProps {
  graph: InteractiveCallGraph;
  selectedId: string | null;
  onSelect: (node: GraphNode | null) => void;
}

const LIBRARY_COLORS = [
  '#6366f1', '#10b981', '#f59e0b', '#ec4899', '#22d3ee',
  '#8b5cf6', '#ef4444', '#84cc16', '#f97316', '#14b8a6',
];

function libraryColor(lib: string | null): string {
  if (!lib) return '#64748b';
  let h = 0;
  for (let i = 0; i < lib.length; i++) h = (h * 31 + lib.charCodeAt(i)) >>> 0;
  return LIBRARY_COLORS[h % LIBRARY_COLORS.length];
}

function nodeRadius(n: GraphNode): number {
  const base = 5 + Math.min(10, Math.log2(1 + n.call_count + n.called_by_count) * 2);
  return Math.max(base, n.is_entry ? 12 : 6);
}

type SimNode = GraphNode & d3.SimulationNodeDatum;
const MAX_NODES = 300;

export default function ForceGraph({ graph, selectedId, onSelect }: ForceGraphProps) {
  const svgRef = useRef<SVGSVGElement>(null);
  const simRef = useRef<d3.Simulation<SimNode, undefined> | null>(null);
  const nodeSelRef = useRef<d3.Selection<SVGGElement, SimNode, SVGGElement, unknown> | null>(null);


  // ---- Effect 1: build simulation + SVG. Re-runs only on graph change,
  //      NOT on selection — prevents the "fly off screen" bug. ----
  useEffect(() => {
    const el = svgRef.current;
    if (!el || !graph) return;

    const width = el.clientWidth || 900;
    const height = 600;
    d3.select(el).selectAll('*').remove();

    const svg = d3.select(el).attr('viewBox', `0 0 ${width} ${height}`);
    const root = svg.append('g');

    svg.call(
      d3.zoom<SVGSVGElement, unknown>()
        .scaleExtent([0.08, 10])
        .on('zoom', (ev: d3.D3ZoomEvent<SVGSVGElement, unknown>) =>
          root.attr('transform', ev.transform.toString())),
    );

    // Arrow marker for directed edges.
    svg.append('defs').append('marker')
      .attr('id', 'arrowhead').attr('viewBox', '0 -5 10 10')
      .attr('refX', 14).attr('refY', 0).attr('markerWidth', 6)
      .attr('markerHeight', 6).attr('orient', 'auto')
      .append('path').attr('d', 'M0,-5L10,0L0,5').attr('fill', '#64748b');

    // Legend
    const libs = Array.from(new Set(graph.nodes.map((n) => n.library).filter(Boolean))) as string[];
    const legend = svg.append('g').attr('transform', `translate(12, 12)`);
    libs.slice(0, 10).forEach((lib, i) => {
      legend.append('circle').attr('cx', 6).attr('cy', i * 16 + 4).attr('r', 4).attr('fill', libraryColor(lib));
      legend.append('text').attr('x', 14).attr('y', i * 16 + 8)
        .attr('font-size', 10).attr('fill', '#cbd5e1').text(lib);
    });

    // Cap node count — keep the most-connected.
    const allNodes = [...graph.nodes].sort(
      (a, b) => b.call_count + b.called_by_count - (a.call_count + a.called_by_count));
    const visible = allNodes.slice(0, MAX_NODES);
    const nodes: SimNode[] = visible.map((n) => ({ ...n }));
    const nodeById = new Map<string, SimNode>(nodes.map((n) => [n.id, n]));
    const links = graph.edges
      .map((e: GraphEdge) => ({ source: e.source, target: e.target }))
      .filter((l) => nodeById.has(l.source) && nodeById.has(l.target));

    // Pre-position nodes in a golden-angle spiral so the simulation starts from
    // a sensible layout instead of randomized points (which causes a violent,
    // CPU-heavy first burst and the node positions flying everywhere).
    const cx = width / 2, cy = height / 2;
    const maxR = Math.min(width, height) * 0.42;
    nodes.forEach((d, i) => {
      const t = i / Math.max(nodes.length, 1);
      const ang = Math.PI * 2 * t * 2.4; // golden-angle-ish
      d.x = cx + Math.cos(ang) * maxR * Math.sqrt(t);
      d.y = cy + Math.sin(ang) * maxR * Math.sqrt(t);
    });

    // Tuned forces: moderate repulsion, gentle center pull, strong collision.
    const sim = d3.forceSimulation<SimNode>(nodes)
      .force('link', d3.forceLink(links).id((d: unknown) => (d as GraphNode).id).distance(60).strength(0.3))
      .force('charge', d3.forceManyBody<SimNode>().strength(-180))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collide', d3.forceCollide<SimNode>().radius((d) => nodeRadius(d) + 8).strength(0.9))
      .force('x', d3.forceX<SimNode>(width / 2).strength(0.04))
      .force('y', d3.forceY<SimNode>(height / 2).strength(0.04))
      // Settle much faster so the UI doesn't hang animating for seconds.
      .alphaDecay(0.12)
      .alphaMin(0.05);
    simRef.current = sim;

    // Links (curved paths with arrowheads)
    const link = root.append('g').selectAll('path').data(links).join('path')
      .attr('fill', 'none').attr('stroke', '#475569')
      .attr('stroke-opacity', 0.35).attr('stroke-width', 1)
      .attr('marker-end', 'url(#arrowhead)');

    const drag = d3.drag<SVGGElement, SimNode>()
      .on('start', (ev, d) => {
        if (!ev.active) sim.alphaTarget(0.3).restart();
        d.fx = d.x; d.fy = d.y;
      })
      .on('drag', (ev, d) => { d.fx = ev.x; d.fy = ev.y; })
      .on('end', (ev, d) => {
        if (!ev.active) sim.alphaTarget(0);
        d.fx = null; d.fy = null;
      });

    const nodeSel = root.append('g').selectAll('g').data(nodes).join('g')
      .call(drag as any)
      .on('click', (ev, d) => { ev.stopPropagation(); onSelect(d); })
      .style('cursor', 'pointer');
    nodeSelRef.current = nodeSel as any;

    nodeSel.append('circle')
      .attr('r', nodeRadius)
      .attr('fill', (d) => libraryColor(d.library ?? null))
      .attr('fill-opacity', 0.85)
      .attr('stroke', (d) => d.is_entry ? '#f59e0b' : d.is_external ? '#94a3b8' : 'none')
      .attr('stroke-width', (d) => d.is_entry ? 2.5 : 1.5);

    nodeSel.append('title').text(
      (d) => `${d.name}\naddr 0x${d.address.toString(16).toUpperCase()}\nlib ${d.library ?? '—'}\ncalls ${d.call_count} · called-by ${d.called_by_count}`);

    nodeSel.filter((d) => d.is_named || d.is_entry).append('text')
      .attr('dx', 0).attr('dy', (d) => -nodeRadius(d) - 4)
      .attr('text-anchor', 'middle').attr('font-size', 9.5)
      .attr('font-family', 'JetBrains Mono, monospace')
      .attr('fill', '#cbd5e1')
      .text((d) => d.name.length > 20 ? d.name.slice(0, 18) + '…' : d.name);

    const linkArc = (d: any) => {
      const sx = d.source.x ?? 0, sy = d.source.y ?? 0;
      const tx = d.target.x ?? 0, ty = d.target.y ?? 0;
      const dr = Math.sqrt((tx - sx) ** 2 + (ty - sy) ** 2) || 1;
      return `M${sx},${sy}A${dr * 1.5},${dr * 1.5} 0 0,1${tx},${ty}`;
    };

    let rafPending = false;
    const draw = () => {
      rafPending = false;
      // Clamp nodes to the viewport so they can't escape.
      for (const d of nodes) {
        const r = nodeRadius(d);
        d.x = Math.max(r, Math.min(width - r, d.x ?? 0));
        d.y = Math.max(r, Math.min(height - r, d.y ?? 0));
      }
      link.attr('d', linkArc);
      nodeSel.attr('transform', (d) => `translate(${d.x},${d.y})`);
    };
    sim.on('tick', () => {
      // Throttle DOM updates to one per animation frame — the simulation ticks
      // far faster than the screen refreshes, so this avoids wasted layout work
      // and keeps the UI responsive.
      if (!rafPending) {
        rafPending = true;
        requestAnimationFrame(draw);
      }
    });

    // Kick off one draw immediately (pre-positioned), then let the sim settle.
    draw();
    sim.restart();

    return () => { sim.stop(); simRef.current = null; nodeSelRef.current = null; };
  }, [graph, onSelect]); // ← NO selectedId!

  // ---- Effect 2: update highlight styling on selection change (no rebuild). ----
  useEffect(() => {
    const nodeSel = nodeSelRef.current;
    if (!nodeSel) return;
    nodeSel.select('circle')
      .attr('fill-opacity', (d: any) => (selectedId && d.id !== selectedId ? 0.2 : 0.85))
      .attr('stroke', (d: any) => {
        if (d.id === selectedId) return '#f8fafc';
        if (d.is_entry) return '#f59e0b';
        if (d.is_external) return '#94a3b8';
        return 'none';
      })
      .attr('stroke-width', (d: any) => (d.id === selectedId ? 3 : d.is_entry ? 2.5 : 1.5));
  }, [selectedId]);

  return (
    <div className="overflow-hidden rounded-lg border border-app-border bg-app-panel-soft">
      <svg ref={svgRef} className="block h-[62vh] w-full" />
      <div className="border-t border-app-border px-3 py-1.5 text-xs text-fg-muted">
        Drag nodes to reposition · scroll to zoom · click a node for callers/callees
        {graph.nodes.length > MAX_NODES && ` · showing top ${MAX_NODES} of ${graph.nodes.length} nodes`}
      </div>
    </div>
  );
}