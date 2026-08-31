import { useEffect, useRef } from 'react';
import * as d3 from 'd3';
import type { GraphEdge, GraphNode, InteractiveCallGraph } from '../../types';

export interface ForceGraphProps {
  graph: InteractiveCallGraph;
  selectedId: string | null;
  onSelect: (node: GraphNode | null) => void;
}

/** Deterministic color per library, cycling a fixed palette. */
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

/** A graph node augmented with D3's simulation datum fields (x/y/vx/vy). */
type SimNode = GraphNode & d3.SimulationNodeDatum;

export default function ForceGraph({ graph, selectedId, onSelect }: ForceGraphProps) {
  const svgRef = useRef<SVGSVGElement>(null);

  useEffect(() => {
    const el = svgRef.current;
    if (!el || !graph) return;

    const width = el.clientWidth || 900;
    const height = 620;
    d3.select(el).selectAll('*').remove();

    const svg = d3.select(el).attr('viewBox', `0 0 ${width} ${height}`);
    const root = svg.append('g');

    svg.call(
      d3
        .zoom<SVGSVGElement, unknown>()
        .scaleExtent([0.08, 10])
        .on('zoom', (ev: d3.D3ZoomEvent<SVGSVGElement, unknown>) => root.attr('transform', ev.transform.toString())),
    );

    // A small legend for libraries.
    const libs = Array.from(new Set(graph.nodes.map((n) => n.library).filter(Boolean))) as string[];
    const legend = svg.append('g').attr('transform', `translate(12, 12)`);
    libs.slice(0, 12).forEach((lib, i) => {
      legend
        .append('circle')
        .attr('cx', 6)
        .attr('cy', i * 16 + 4)
        .attr('r', 4)
        .attr('fill', libraryColor(lib));
      legend
        .append('text')
        .attr('x', 14)
        .attr('y', i * 16 + 8)
        .attr('font-size', 10)
        .attr('fill', '#cbd5e1')
        .text(lib);
    });

    const nodes: SimNode[] = graph.nodes.map((n) => ({ ...n }));
    const nodeById = new Map<string, GraphNode>(nodes.map((n) => [n.id, n]));
    const links = graph.edges
      .map((e: GraphEdge) => ({ source: e.source, target: e.target }))
      .filter((l) => nodeById.has(l.source) && nodeById.has(l.target));

    const sim = d3
      .forceSimulation(nodes)
      .force(
        'link',
        d3.forceLink(links).id((d: unknown) => (d as GraphNode).id).distance(70).strength(0.4),
      )
      .force('charge', d3.forceManyBody<SimNode>().strength(-380))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collide', d3.forceCollide<SimNode>().radius((d) => nodeRadius(d) + 10).strength(0.8));

    const link = root
      .append('g')
      .selectAll('line')
      .data(links)
      .join('line')
      .attr('stroke', '#475569')
      .attr('stroke-opacity', 0.45)
      .attr('stroke-width', 1);

    const drag = d3
      .drag<SVGGElement, SimNode>()
      .on('start', (ev, d) => {
        if (!ev.active) sim.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
      })
      .on('drag', (ev, d) => {
        d.fx = ev.x;
        d.fy = ev.y;
      })
      .on('end', (ev, d) => {
        if (!ev.active) sim.alphaTarget(0);
        d.fx = null;
        d.fy = null;
      });

    const node = root
      .append('g')
      .selectAll('g')
      .data(nodes)
      .join('g')
      .call(drag as any)
      .on('click', (_ev, d) => onSelect(d))
      .style('cursor', 'pointer');

    node
      .append('circle')
      .attr('r', nodeRadius)
      .attr('fill', (d) => libraryColor(d.library ?? null))
      .attr('fill-opacity', (d) => (selectedId && d.id !== selectedId ? 0.25 : 0.9))
      .attr('stroke', (d) => {
        if (d.id === selectedId) return '#f8fafc';
        if (d.is_entry) return '#f59e0b';
        if (d.is_external) return '#94a3b8';
        return 'none';
      })
      .attr('stroke-width', (d) => (d.id === selectedId || d.is_entry ? 2.5 : 1.5));

    node
      .append('title')
      .text(
        (d) =>
          `${d.name}\naddr 0x${d.address.toString(16).toUpperCase()}\nlib ${d.library ?? '—'}\ncalls ${d.call_count} · called-by ${d.called_by_count}`,
      );

    node
      .filter((d) => d.is_named || d.id === selectedId || d.is_entry)
      .append('text')
      .attr('dx', 0)
      .attr('dy', (d) => -nodeRadius(d) - 4)
      .attr('text-anchor', 'middle')
      .attr('font-size', 10.5)
      .attr('font-family', 'JetBrains Mono, monospace')
      .attr('fill', '#e2e8f0')
      .text((d) => d.name);

    sim.on('tick', () => {
      link
        .attr('x1', (d: any) => d.source.x)
        .attr('y1', (d: any) => d.source.y)
        .attr('x2', (d: any) => d.target.x)
        .attr('y2', (d: any) => d.target.y);
      node.attr('transform', (d) => `translate(${d.x},${d.y})`);
    });

    return () => {
      sim.stop();
    };
  }, [graph, selectedId, onSelect]);

  return (
    <div className="overflow-hidden rounded-lg border border-app-border bg-app-panel-soft">
      <svg ref={svgRef} className="block h-[62vh] w-full" />
      <div className="border-t border-app-border px-3 py-1.5 text-xs text-fg-muted">
        Drag to pan · scroll to zoom · drag nodes to reposition · click a node for callers/callees
      </div>
    </div>
  );
}