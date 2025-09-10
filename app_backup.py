import streamlit as st
import re
import statistics
from io import StringIO
import pandas as pd
from collections import defaultdict

# --- Constantes ---
IP_PATTERN = re.compile(r'(\d+\.\d+\.\d+\.\d+:\d+)')
ID_PATTERN = re.compile(r'ID_0*(\d+)')
LTRX_PATTERN = re.compile(r'L?TRXMINUTO=([\d.]+)')
FVO_PATTERN = re.compile(r'FVO=([\d\.]+)')
VO_PATTERN = re.compile(r'VO=([\d\.]+)')
PR_PATTERN = re.compile(r'PR=([\d\.]+)')
FCR_PATTERN = re.compile(r'FCR=([\w]+)')
ERROR_KEYWORDS = ["ERROR", "FALLA", "FAIL", "EXCEPTION"]

# --- Funciones de Procesamiento y Análisis (con caché) ---

def parse_log_files(log_lines):
    """Parsea las líneas de log y las agrupa por surtidor (IP+ID)."""
    surtidores = {}  # (ip, id) -> list of log dicts
    id_to_ips = defaultdict(set)  # id -> set of IPs
    ip_to_ids = defaultdict(set)  # ip -> set of IDs

    total = 0
    procesadas = 0
    descartadas = 0
    ejemplos_descartadas = []
    for idx, line in enumerate(log_lines):
        total += 1
        # Extraer IP
        ip_match = IP_PATTERN.search(line)
        if not ip_match:
            descartadas += 1
            if len(ejemplos_descartadas) < 3:
                ejemplos_descartadas.append(f"Línea {idx+1}: {line[:100]}")
            continue

        ip = ip_match.group(1)
        
        # Extraer ID del surtidor
        id_match = ID_PATTERN.search(line)
        if id_match:
            surtidor_id = int(id_match.group(1))
            id_to_ips[surtidor_id].add(ip)
            ip_to_ids[ip].add(surtidor_id)
        else:
            # Eventos sin ID específico van al grupo 0
            surtidor_id = 0
        
        log_entry = {
            "line": idx + 1,
            "text": line.strip(),
            "ip": ip,
            "id": surtidor_id
        }

        key = (ip, surtidor_id)
        if key not in surtidores:
            surtidores[key] = []
        surtidores[key].append(log_entry)
        procesadas += 1

    # Información de procesamiento
    with st.expander("📊 Estadísticas de Procesamiento de Log", expanded=False):
        st.metric("Total líneas", total)
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Líneas procesadas", procesadas)
        with col2:
            st.metric("Líneas descartadas", descartadas)
        
        if ejemplos_descartadas:
            st.write("**Ejemplos de líneas descartadas:**")
            for ej in ejemplos_descartadas:
                st.code(ej, language="text")

    return surtidores, dict(id_to_ips), dict(ip_to_ids)

def analyze_surtidor(surtidor_ip, surtidor_num, logs, ltrx_factor, salto_umbral, preset_over_factor, preset_under_factor):
    """Analiza los logs de un surtidor específico y detecta anomalías."""
    ltrx_values = []
    fvo_values = []
    vo_values = []
    pr_values = []
    fcr_values = []
    eventos_importantes = []
    eventos_error = []
    mangueras_info = {}

    for log_entry in logs:
        text = log_entry["text"]
        
        # Extraer valores de LTRX
        ltrx_match = LTRX_PATTERN.search(text)
        if ltrx_match:
            try:
                ltrx = float(ltrx_match.group(1))
                ltrx_values.append((log_entry["line"], ltrx, text))
            except ValueError:
                pass
        
        # Extraer FVO
        fvo_match = FVO_PATTERN.search(text)
        if fvo_match:
            try:
                fvo = float(fvo_match.group(1))
                fvo_values.append((log_entry["line"], fvo, text))
            except ValueError:
                pass
        
        # Extraer VO
        vo_match = VO_PATTERN.search(text)
        if vo_match:
            try:
                vo = float(vo_match.group(1))
                vo_values.append((log_entry["line"], vo, text))
            except ValueError:
                pass
        
        # Extraer PR
        pr_match = PR_PATTERN.search(text)
        if pr_match:
            try:
                pr = float(pr_match.group(1))
                pr_values.append((log_entry["line"], pr, text))
            except ValueError:
                pass
        
        # Extraer FCR
        fcr_match = FCR_PATTERN.search(text)
        if fcr_match:
            fcr = fcr_match.group(1)
            fcr_values.append((log_entry["line"], fcr, text))
        
        # Eventos importantes
        if any(evento in text for evento in ["EVT_PUMP_NEW_TRANSACTION", "EVT_PUMP_START_AUTHORIZE", "EVT_PUMP_END_AUTHORIZE"]):
            eventos_importantes.append(log_entry)
        
        # Eventos de error
        if any(keyword in text.upper() for keyword in ERROR_KEYWORDS) or "ST=ERROR" in text:
            eventos_error.append(log_entry)

    # Análisis de saltos en LTRX
    saltos_ltrx = []
    if len(ltrx_values) > 1:
        for i in range(1, len(ltrx_values)):
            prev_val = ltrx_values[i-1][1]
            curr_val = ltrx_values[i][1]
            diff = curr_val - prev_val
            if abs(diff) >= salto_umbral:
                saltos_ltrx.append({
                    'linea': ltrx_values[i][0],
                    'anterior': prev_val,
                    'actual': curr_val,
                    'diferencia': diff,
                    'texto': ltrx_values[i][2]
                })

    # Análisis estadístico de LTRX
    stats_ltrx = {}
    if ltrx_values:
        values_only = [v[1] for v in ltrx_values]
        stats_ltrx = {
            'promedio': statistics.mean(values_only),
            'mediana': statistics.median(values_only),
            'minimo': min(values_only),
            'maximo': max(values_only),
            'total_lecturas': len(values_only)
        }
    
    return {
        'ltrx_values': ltrx_values,
        'fvo_values': fvo_values,
        'vo_values': vo_values,
        'pr_values': pr_values,
        'fcr_values': fcr_values,
        'eventos_importantes': eventos_importantes,
        'eventos_error': eventos_error,
        'saltos_ltrx': saltos_ltrx,
        'stats_ltrx': stats_ltrx,
        'mangueras_info': mangueras_info
    }

def display_analysis_results(surtidor_num, surtidor_ip, logs, analysis_results):
    """Muestra los resultados del análisis con mejor visualización."""
    
    # Header del surtidor con estilo mejorado
    st.markdown(f"""
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                padding: 20px; border-radius: 15px; margin: 20px 0;">
        <h2 style="color: white; margin: 0; text-align: center;">
            ⛽ Surtidor {surtidor_num} - IP: {surtidor_ip}
        </h2>
        <p style="color: #e8f0fe; text-align: center; margin: 10px 0 0 0;">
            Total de eventos: {len(logs)} | Análisis detallado a continuación
        </p>
    </div>
    """, unsafe_allow_html=True)

    # Resumen ejecutivo en columnas
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            label="📊 Lecturas LTRX",
            value=analysis_results['stats_ltrx'].get('total_lecturas', 0)
        )
    
    with col2:
        eventos_importantes = len(analysis_results['eventos_importantes'])
        st.metric(
            label="✨ Eventos Importantes", 
            value=eventos_importantes,
            delta=f"+{eventos_importantes}" if eventos_importantes > 0 else None
        )
    
    with col3:
        eventos_error = len(analysis_results['eventos_error'])
        st.metric(
            label="⚠️ Eventos de Error",
            value=eventos_error,
            delta=f"+{eventos_error}" if eventos_error > 0 else None
        )
    
    with col4:
        saltos = len(analysis_results['saltos_ltrx'])
        st.metric(
            label="📈 Saltos Detectados",
            value=saltos,
            delta=f"+{saltos}" if saltos > 0 else None
        )

    # Estadísticas de LTRX mejoradas
    if analysis_results['stats_ltrx']:
        with st.expander("📈 Estadísticas Detalladas de LTRX", expanded=True):
            stats = analysis_results['stats_ltrx']
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Promedio", f"{stats['promedio']:.2f}")
                st.metric("Mínimo", f"{stats['minimo']:.2f}")
            with col2:
                st.metric("Mediana", f"{stats['mediana']:.2f}")
                st.metric("Máximo", f"{stats['maximo']:.2f}")
            with col3:
                rango = stats['maximo'] - stats['minimo']
                st.metric("Rango", f"{rango:.2f}")
                st.metric("Total Lecturas", stats['total_lecturas'])

    # Eventos importantes con mejor formato
    if analysis_results['eventos_importantes']:
        with st.expander("✨ Eventos Importantes", expanded=True):
            for evento in analysis_results['eventos_importantes']:
                st.markdown(f"""
                <div style="background-color: #e8f5e8; padding: 10px; margin: 5px 0; 
                           border-left: 4px solid #4caf50; border-radius: 5px;">
                    <strong>Línea {evento['line']}:</strong><br>
                    <code>{evento['text']}</code>
                </div>
                """, unsafe_allow_html=True)

    # Eventos de error con estilo de alerta
    if analysis_results['eventos_error']:
        with st.expander("⚠️ Eventos de Error", expanded=True):
            for evento in analysis_results['eventos_error']:
                st.markdown(f"""
                <div style="background-color: #ffebee; padding: 10px; margin: 5px 0; 
                           border-left: 4px solid #f44336; border-radius: 5px;">
                    <strong>Línea {evento['line']}:</strong><br>
                    <code>{evento['text']}</code>
                </div>
                """, unsafe_allow_html=True)

    # Saltos de LTRX con alertas visuales
    if analysis_results['saltos_ltrx']:
        with st.expander("🚨 Saltos Detectados en LTRX", expanded=True):
            for salto in analysis_results['saltos_ltrx']:
                color = "#ff9800" if abs(salto['diferencia']) > 50 else "#2196f3"
                st.markdown(f"""
                <div style="background-color: #fff3e0; padding: 15px; margin: 10px 0; 
                           border-left: 4px solid {color}; border-radius: 5px;">
                    <strong>Línea {salto['linea']}:</strong> 
                    Salto de <strong>{salto['diferencia']:.2f}</strong> 
                    ({salto['anterior']:.2f} → {salto['actual']:.2f})<br>
                    <code style="font-size: 0.9em;">{salto['texto']}</code>
                </div>
                """, unsafe_allow_html=True)

def setup_sidebar():
    """Configura la barra lateral con parámetros de análisis mejorada."""
    st.sidebar.markdown("""
    <div style="background-color: #f8f9fa; padding: 15px; border-radius: 10px; margin-bottom: 20px;">
        <h3 style="margin: 0; color: #495057;">⚙️ Configuración</h3>
        <p style="margin: 5px 0 0 0; color: #6c757d; font-size: 0.9em;">
            Ajusta los parámetros de análisis
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Carga de archivos mejorada
    st.sidebar.markdown("### 📁 Cargar Archivos")
    data_files = st.sidebar.file_uploader(
        "Selecciona archivos de log", 
        type=["txt", "log"], 
        accept_multiple_files=True,
        help="Soporta archivos .txt y .log con logs de surtidores"
    )
    
    if data_files:
        st.sidebar.success(f"✅ {len(data_files)} archivo(s) cargado(s)")
    
    # Parámetros de análisis organizados
    st.sidebar.markdown("### 🔧 Parámetros de Análisis")
    
    with st.sidebar.expander("⛽ Configuración de Combustible", expanded=True):
        ltrx_factor = st.number_input(
            "Factor LTRX", 
            value=1000.0, 
            step=100.0,
            help="Factor de conversión para lecturas LTRX"
        )
        salto_umbral = st.number_input(
            "Umbral de Salto LTRX", 
            value=50.0, 
            step=10.0,
            help="Diferencia mínima para considerar un salto anómalo"
        )
    
    with st.sidebar.expander("🎯 Configuración de Preset", expanded=False):
        preset_over_factor = st.number_input(
            "Factor Preset Over", 
            value=1.05, 
            step=0.01,
            help="Factor para detectar preset superior"
        )
        preset_under_factor = st.number_input(
            "Factor Preset Under", 
            value=0.95, 
            step=0.01,
            help="Factor para detectar preset inferior"
        )
    
    st.sidebar.markdown("---")
    st.sidebar.markdown("### ℹ️ Información")
    st.sidebar.info(
        "💡 **Tip:** Los archivos se procesan automáticamente. "
        "Ajusta los parámetros para personalizar el análisis."
    )
    
    return data_files, ltrx_factor, salto_umbral, preset_over_factor, preset_under_factor

def main():
    # Configuración de página mejorada
    st.set_page_config(
        page_title="Analizador de Logs de Surtidores",
        page_icon="⛽",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # Header principal con diseño mejorado
    st.markdown("""
    <div style="background: linear-gradient(90deg, #1f4e79, #2e86ab); padding: 20px; border-radius: 10px; margin-bottom: 20px;">
        <h1 style="color: white; margin: 0; text-align: center;">⛽ Analizador de Logs de Surtidores</h1>
        <p style="color: #e8f4f8; text-align: center; margin: 10px 0 0 0;">
            Sistema inteligente de análisis y monitoreo de surtidores de combustible
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    # Información del sistema
    col1, col2, col3 = st.columns(3)
    with col1:
        st.info("🔍 **Análisis Automático**\nDetección de patrones y anomalías")
    with col2:
        st.success("🚨 **Alertas Inteligentes**\nProblemas de red y energía")
    with col3:
        st.warning("📊 **Reportes Detallados**\nExportación y visualización")
    
    data_files, ltrx_factor, salto_umbral, preset_over_factor, preset_under_factor = setup_sidebar()

    if not data_files:
        st.markdown("""
        <div style="text-align: center; padding: 40px;">
            <h3>🚀 ¡Comienza tu análisis!</h3>
            <p>Carga uno o más archivos de log desde la barra lateral para iniciar el análisis automático.</p>
            <p style="color: #666;">Formatos soportados: .txt, .log y archivos de texto plano</p>
        </div>
        """, unsafe_allow_html=True)
        st.stop()

    # Procesar archivos y obtener surtidores
    with st.spinner("📋 Procesando archivos de log..."):
        all_lines = []
        for data_file in data_files:
            all_lines.extend(data_file.read().decode(errors='ignore').splitlines())
        log_lines = tuple(all_lines)
        surtidores, id_to_ips, ip_to_ids = parse_log_files(log_lines)

    if not surtidores:
        st.error("❌ No se pudo encontrar ningún surtidor en los archivos de log.")
        st.markdown("**Verifica que los archivos contengan:**")
        st.markdown("- Direcciones IP válidas")
        st.markdown("- IDs de surtidor (ID_XXX)")
        st.markdown("- Eventos de surtidor")
        st.stop()

    # Definir claves y etiquetas de surtidores para la UI
    surtidor_keys = sorted(surtidores.keys(), key=lambda k: (k[1], k[0]))  # (ip, id)
    surtidor_labels = [f"Surtidor {k[1]} - IP {k[0]}" for k in surtidor_keys]

    # --- SISTEMA DE ALERTAS INTELIGENTE ---
    st.markdown("""
    <div style="background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 20px 0;">
        <h3 style="margin-top: 0; color: #856404;">🚨 Sistema de Alertas Automático</h3>
        <p style="margin-bottom: 0; color: #664d03;">
            Monitoreo en tiempo real de problemas críticos en la operación
        </p>
    </div>
    """, unsafe_allow_html=True)
    
    alert_count = 0
    
    # Alerta 1: Surtidores con más de una IP (problema de red)
    config_alerts = {}
    for idn, ips in id_to_ips.items():
        # Solo marcar como problema si hay más de una IP realmente distinta (no repeticiones)
        # Ignorar IPs Fusion fija en la alerta
        ips_reales = [ip for ip in ips if not ip.startswith('195.180.178')]
        if len(ips_reales) > 1:
            config_alerts[idn] = sorted(ips_reales)

    if config_alerts:
        alert_count += 1
        with st.expander("🔴 Alerta de Problema de Red", expanded=True):
            st.error("¡Se detectaron surtidores con múltiples direcciones IP! Esto puede indicar un problema de configuración de red.")
            st.write(f"**Surtidores afectados:** {len(config_alerts)}")
            for idn, ips in config_alerts.items():
                st.markdown(f"- **Surtidor ID {idn}** se ha comunicado desde las siguientes IPs: `{', '.join(ips)}`")

    # Alerta 2: Posible corte de energía (2+ surtidores en error en ventanas de 5 minutos)
    from datetime import datetime, timedelta
    error_times = {}  # id -> datetime del primer error
    surtidor_ids_unicos = set(idn for ip, idn in surtidor_keys if idn > 0)  # Solo IDs reales, no el 0
    
    for key in surtidor_keys:
        ip, idn = key
        if idn == 0:  # Ignorar el grupo de eventos sin ID
            continue
            
        logs = surtidores[key]
        logs_id0 = surtidores.get((ip, 0), [])
        logs_all = sorted(logs + logs_id0, key=lambda l: l['line'])
        
        for l in logs_all:
            texto = l["text"].upper()
            if any(k in texto for k in ERROR_KEYWORDS) or "ST=ERROR" in texto:
                # Extraer timestamp
                try:
                    ts = l["text"].split()[0] + " " + l["text"].split()[1].split(",")[0]
                    dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
                    if idn not in error_times or dt < error_times[idn]:
                        error_times[idn] = dt
                except Exception as e:
                    # Intentar otros formatos de timestamp
                    try:
                        # Para formato como: 2025-09-07 23:08:01,160
                        ts_parts = l["text"].split()
                        if len(ts_parts) >= 2:
                            ts = ts_parts[0] + " " + ts_parts[1].split(",")[0]
                            dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
                            if idn not in error_times or dt < error_times[idn]:
                                error_times[idn] = dt
                    except Exception:
                        continue
                break  # Solo el primer error por surtidor
    
    # Verificar si hay 2+ surtidores con error en ventanas de tiempo relacionadas (5 minutos)
    total_surtidores = len(surtidor_ids_unicos)
    
    if len(error_times) >= 2 and error_times:
        # Buscar grupos de errores en ventanas de 5 minutos
        times_sorted = sorted(error_times.items(), key=lambda x: x[1])
        error_groups = []
        
        for i in range(len(times_sorted)):
            current_time = times_sorted[i][1]
            group = [times_sorted[i]]
            
            # Buscar otros errores dentro de 5 minutos
            for j in range(i + 1, len(times_sorted)):
                if times_sorted[j][1] - current_time <= timedelta(minutes=5):
                    group.append(times_sorted[j])
                else:
                    break
            
            if len(group) >= 2:
                error_groups.append(group)
        
        # Mostrar alertas para grupos encontrados
        for idx, group in enumerate(error_groups):
            if len(group) >= 2:
                alert_count += 1
                tiempo_min = min(item[1] for item in group)
                tiempo_max = max(item[1] for item in group)
                
                with st.expander(f"🔴 Alerta de Problema Masivo #{idx+1}", expanded=True):
                    st.error("¡Múltiples surtidores reportaron error en un intervalo corto! Posible corte de energía eléctrica o pérdida de comunicación.")
                    st.write(f"**Surtidores afectados:** {len(group)} de {total_surtidores} ({len(group)/total_surtidores*100:.1f}%)")
                    st.write(f"**Rango de tiempo:** {tiempo_min.strftime('%H:%M:%S')} - {tiempo_max.strftime('%H:%M:%S')}")
                    st.write(f"**Duración:** {(tiempo_max - tiempo_min).total_seconds():.0f} segundos")
                    
                    # Mostrar detalles de los surtidores afectados
                    st.write("**Surtidores en error:**")
                    for sid, timestamp in sorted(group, key=lambda x: x[1]):
                        st.write(f"- Surtidor ID_{sid:03d}: {timestamp.strftime('%H:%M:%S')}")
                
                # Solo mostrar el primer grupo para evitar duplicados
                break
    
    # Resumen de alertas
    if alert_count == 0:
        st.success("✅ **Todo OK** - No se detectaron problemas críticos en el sistema")
    else:
        st.warning(f"⚠️ **{alert_count} Alerta(s) Activa(s)** - Requiere atención inmediata")

    st.markdown("---")

    # Selección de surtidor para análisis detallado
    st.markdown("### 🔍 Análisis Detallado por Surtidor")
    
    selected_idx = st.selectbox(
        "Selecciona un surtidor para análisis detallado:",
        range(len(surtidor_keys)),
        format_func=lambda i: surtidor_labels[i]
    )

    # Análisis del surtidor seleccionado
    if selected_idx is not None:
        surtidor_key = surtidor_keys[selected_idx]
        surtidor_ip, surtidor_num = surtidor_key

        # Unir todos los logs de esa IP (todos los IDs)
        all_logs = []
        for (ip, idn), logs_list in surtidores.items():
            if ip == surtidor_ip:
                all_logs.extend(logs_list)
        all_logs = sorted(all_logs, key=lambda l: l['line'])

        with st.sidebar:
            st.subheader("📊 Filtros de Análisis")
            min_line = all_logs[0]['line']
            max_line = all_logs[-1]['line']
            line_range = st.slider(
                "Rango de líneas para analizar", 
                min_line, max_line, (min_line, max_line),
                help="Selecciona el rango de líneas del log a analizar"
            )

        filtered_logs = [l for l in all_logs if line_range[0] <= l['line'] <= line_range[1]]
        
        # Marcar visualmente los NEW sin ID
        for l in filtered_logs:
            if l.get('id') == 0 and 'EVT_PUMP_NEW_TRANSACTION' in l['text'] and '[SIN_ID]' not in l['text']:
                l['text'] = l['text'] + ' [SIN_ID]'

        analysis_results = analyze_surtidor(surtidor_ip, surtidor_num, tuple(filtered_logs), ltrx_factor, salto_umbral, preset_over_factor, preset_under_factor)
        display_analysis_results(surtidor_num, surtidor_ip, filtered_logs, analysis_results)

        # Mostrar log completo del surtidor (filtrado) con mejor formato
        with st.expander("📜 Log Completo del Surtidor (Filtrado)", expanded=False):
            st.markdown(f"**Mostrando {len(filtered_logs)} eventos del rango seleccionado**")
            log_text = '\n'.join([f"{l['line']:05d}: {l['text']}" for l in filtered_logs])
            st.code(log_text, language="log")
            
            # Botón de descarga
            st.download_button(
                label="💾 Descargar Log Filtrado",
                data=log_text,
                file_name=f"surtidor_{surtidor_num}_ip_{surtidor_ip.replace(':', '_')}_filtered.log",
                mime="text/plain"
            )

if __name__ == "__main__":
    main()
