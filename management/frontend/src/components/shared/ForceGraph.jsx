import { useEffect, useRef } from 'react'
import * as d3 from 'd3'

// Shared node-link graph (network topology and service map). d3 is already a
// dependency; do not add another graph library.
// nodes: [{id,label,kind,severity?}]  links: [{source,target,weight?,error?}]
export default function ForceGraph({ nodes, links, width = 800, height = 480, onNodeClick, colorFor }) {
  const ref = useRef(null)
  useEffect(() => {
    const svg = d3.select(ref.current)
    svg.selectAll('*').remove()
    if (!nodes?.length) return
    const n = nodes.map(d => ({ ...d }))
    const l = (links || []).map(d => ({ ...d }))
    const color = colorFor || (d => (d.severity >= 4 ? '#ef4444' : d.severity === 3 ? '#f59e0b' : '#60a5fa'))
    const g = svg.append('g')
    svg.call(d3.zoom().scaleExtent([0.3, 4]).on('zoom', e => g.attr('transform', e.transform)))
    const link = g.append('g').attr('stroke-opacity', 0.6).selectAll('line').data(l).join('line')
      .attr('stroke', d => (d.error ? '#ef4444' : '#64748b'))
      .attr('stroke-width', d => Math.max(1, Math.min(6, Math.log10((d.weight || 1) + 1) * 2)))
    const node = g.append('g').selectAll('g').data(n).join('g').style('cursor', onNodeClick ? 'pointer' : 'default')
      .on('click', (_, d) => onNodeClick && onNodeClick(d))
    node.append('circle').attr('r', 9).attr('fill', color).attr('stroke', '#0f172a').attr('stroke-width', 1.5)
    node.append('text').text(d => d.label || d.id).attr('x', 12).attr('y', 4).attr('font-size', 11).attr('fill', 'currentColor')
    const sim = d3.forceSimulation(n)
      .force('link', d3.forceLink(l).id(d => d.id).distance(90))
      .force('charge', d3.forceManyBody().strength(-260))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .on('tick', () => {
        link.attr('x1', d => d.source.x).attr('y1', d => d.source.y).attr('x2', d => d.target.x).attr('y2', d => d.target.y)
        node.attr('transform', d => `translate(${d.x},${d.y})`)
      })
    // Drag nodes; they stay where dropped (double-click releases).
    node.call(d3.drag()
      .on('start', (e, d) => { if (!e.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y })
      .on('drag', (e, d) => { d.fx = e.x; d.fy = e.y })
      .on('end', (e) => { if (!e.active) sim.alphaTarget(0) }))
      .on('dblclick', (e, d) => { e.stopPropagation(); d.fx = null; d.fy = null; sim.alpha(0.3).restart() })
    svg.on('dblclick.zoom', null).style('cursor', 'grab')
    return () => sim.stop()
  }, [nodes, links, width, height, onNodeClick, colorFor])
  return <svg ref={ref} width="100%" viewBox={`0 0 ${width} ${height}`} className="text-siem-text" />
}
