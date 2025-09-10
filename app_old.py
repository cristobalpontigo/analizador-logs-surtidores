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
    
    # Alerta 1: Surtidores con más de una IP (problema de red)
    config_alerts = {}
    for idn, ips in id_to_ips.items():)')
FVO_PATTERN = re.compile(r'FVO=([\d\.]+)')
VO_PATTERN = re.compile(r'VO=([\d\.]+)')
PR_PATTERN = re.compile(r'PR=([\d\.]+)')
FCR_PATTERN = re.compile(r'FCR=([\w]+)')
ERROR_KEYWORDS = ["ERROR", "FALLA", "FAIL", "EXCEPTION"]

st.set_page_config(page_title="Analizador de Logs Avanzado", layout="wide", initial_sidebar_state="expanded")
st.title("🔎 Analizador de Logs Avanzado")

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
        ip = ip_match.group(1) if ip_match else None
        # Extraer ID: buscar ID_00X en la línea (ID_001 es surtidor 1, etc)
        idn = None
        id_match = re.search(r'ID_0*(\d+)', line)
        if id_match:
            idn = int(id_match.group(1))
        else:
            # Fallback: segundo campo numérico después de '- '
            dash_split = line.split('- ', 1)
            if len(dash_split) > 1:
                campos = dash_split[1].split('|')
                if len(campos) > 1 and campos[1].strip().isdigit():
                    idn = int(campos[1].strip())
        ltrx_match = LTRX_PATTERN.search(line)

        # Solo asociar la línea si tiene IP e ID válidos y la IP no es de Fusion fija
        if ip and idn is not None and not ip.startswith('195.180.178.'):
            procesadas += 1
            key = (ip, idn)
            if key not in surtidores:
                surtidores[key] = []
            surtidores[key].append({
                "line": idx + 1,
                "text": line,
                "id": idn,
                "ip": ip,
                "ltrx": float(ltrx_match.group(1)) if ltrx_match else None
            })
            id_to_ips[idn].add(ip)
            ip_to_ids[ip].add(idn)
        # Si es EVT_PUMP_NEW_TRANSACTION y tiene IP válida (no Fusion), incluir aunque no tenga ID
        elif ip and not ip.startswith('195.180.178.') and 'EVT_PUMP_NEW_TRANSACTION' in line:
            procesadas += 1
            key = (ip, 0)  # ID 0 para eventos sin ID
            if key not in surtidores:
                surtidores[key] = []
            surtidores[key].append({
                "line": idx + 1,
                "text": line,
                "id": 0,
                "ip": ip,
                "ltrx": float(ltrx_match.group(1)) if ltrx_match else None
            })
            id_to_ips[0].add(ip)
            ip_to_ids[ip].add(0)
        else:
            descartadas += 1
            if len(ejemplos_descartadas) < 5:
                ejemplos_descartadas.append(line.strip())
    print(f"[DEBUG] Total líneas: {total}, Procesadas: {procesadas}, Descartadas: {descartadas}")
    if ejemplos_descartadas:
        print("[DEBUG] Ejemplos de líneas descartadas:")
        for ej in ejemplos_descartadas:
            print(f"[DEBUG] {ej}")
    return surtidores, id_to_ips, ip_to_ids

def analyze_surtidor(_surtidor_ip, _surtidor_id, _logs, ltrx_factor, salto_umbral, preset_over_factor, preset_under_factor):
    """Analiza los logs de un surtidor para encontrar eventos de interés."""
    errores, saltos_fvo, ltrx_altos, alarmas_preset, ventas_no_cobradas = [], [], [], [], []
    ltrx_vals = [l["ltrx"] for l in _logs if l["ltrx"] is not None and l["ltrx"] < 1000]
    ltrx_prom = statistics.mean(ltrx_vals) if ltrx_vals else 0
    last_fvo = None
    last_preset = None

    for l in _logs:
        # Solo procesar líneas que tengan el ID correcto
        if l.get("id") != _surtidor_id:
            continue

        # Detección de errores
        if any(k in l["text"].upper() for k in ERROR_KEYWORDS):
            errores.append({"Línea": l["line"], "Texto": l["text"]})

        # Detección de LTRXMINUTO anómalo
        if l["ltrx"] is not None and ltrx_prom and l["ltrx"] > ltrx_prom * ltrx_factor:
            ltrx_altos.append({"Línea": l["line"], "LTRXMINUTO": l["ltrx"], "Promedio": f"{ltrx_prom:.2f}", "Texto": l["text"]})

        # Capturar el último preset establecido SOLO si la línea es del surtidor
        pr_match = PR_PATTERN.search(l["text"])
        if pr_match:
            last_preset = float(pr_match.group(1))

        # Análisis de transacciones al finalizar SOLO si la línea es del surtidor
        if "EVT_PUMP_NEW_TRANSACTION" in l["text"]:
            fvo_match = FVO_PATTERN.search(l["text"])
            vo_match = VO_PATTERN.search(l["text"])
            fcr_match = FCR_PATTERN.search(l["text"])

            fvo = float(fvo_match.group(1)) if fvo_match else None
            vo = float(vo_match.group(1)) if vo_match else None
            fcr = fcr_match.group(1) if fcr_match else None
            monto = last_preset

            # Detección de salto de numeral
            if fcr in ["ReadFromTotalizers", "PumpDisconnected"]:
                saltos_fvo.append({"Línea": l["line"], "FVO": fvo, "FVO anterior": last_fvo, "Motivo": f"FCR={fcr}", "Texto": l["text"]})
            elif fcr == "NormalCompletion" and all(v is not None for v in [last_fvo, fvo, vo]):
                if abs((last_fvo + vo) - fvo) > salto_umbral:
                    saltos_fvo.append({"Línea": l["line"], "FVO": fvo, "FVO anterior": last_fvo, "VO": vo, "Motivo": "Diferencia matemática", "Texto": l["text"]})
            
            # Solo actualizar last_fvo si la línea es del surtidor
            if fvo is not None:
                last_fvo = fvo

            # Detección de alarma sobre preset y venta no cobrada
            if monto and fvo and monto > 0:
                if fvo > monto * preset_over_factor:
                    alarmas_preset.append({"Línea": l["line"], "FVO": fvo, "Preset": monto, "Texto": l["text"]})
                elif fvo < monto * preset_under_factor:
                    ventas_no_cobradas.append({"Línea": l["line"], "FVO": fvo, "Preset": monto, "Texto": l["text"]})
            
            # Solo limpiar last_preset si la línea es del surtidor
            last_preset = None

    return errores, saltos_fvo, ltrx_altos, ltrx_prom, alarmas_preset, ventas_no_cobradas

# --- Funciones de UI ---

def setup_sidebar():
    """Configura la barra lateral con los controles de la aplicación."""
    with st.sidebar:
        st.header("Configuración")
        data_files = st.file_uploader(
            "Carga uno o más archivos de log (cualquier extensión)",
            accept_multiple_files=True,
            key="file_uploader_main"
        )
        
        st.subheader("Parámetros de Análisis")
        ltrx_factor = st.slider("Factor de LPM alto", 1.0, 20.0, 5.0, 0.1, help="LTRXMINUTO > promedio * este factor")
        salto_umbral = st.number_input("Umbral de salto de numeral (litros)", 0.1, 10.0, 1.0, 0.1)
        
        col1, col2 = st.columns(2)
        preset_over_factor = col1.number_input("Factor sobre-preset", 1.01, 2.0, 1.05, 0.01, help="FVO > Preset * este factor")
        preset_under_factor = col2.number_input("Factor sub-preset", 0.1, 0.99, 0.5, 0.05, help="FVO < Preset * este factor")

    return data_files, ltrx_factor, salto_umbral, preset_over_factor, preset_under_factor

def display_analysis_results(surtidor_num, ip, logs, analysis_results):
    """Muestra los resultados del análisis para un surtidor."""
    errores, saltos_fvo, ltrx_altos, ltrx_prom, alarmas_preset, ventas_no_cobradas = analysis_results
    
    st.markdown(f"### Surtidor {surtidor_num} ({ip})")
    
    # Métricas
    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Errores", len(errores))
    col2.metric("Saltos Numeral", len(saltos_fvo))
    col3.metric("LPM Anómalo", len(ltrx_altos))
    col4.metric("Alarma Preset", len(alarmas_preset))
    col5.metric("Venta No Cobrada", len(ventas_no_cobradas))
    
    st.write(f"**Promedio LTRXMINUTO:** {ltrx_prom:.2f}" if ltrx_prom else "No hay datos de LTRXMINUTO")
    st.write(f"**Total de líneas:** {len(logs)}")

    # Pestañas con detalles
    tab_titles = [f"Errores ({len(errores)})", f"Saltos Numeral ({len(saltos_fvo)})", f"LPM Anómalo ({len(ltrx_altos)})", f"Alarma Preset ({len(alarmas_preset)})", f"Venta No Cobrada ({len(ventas_no_cobradas)})"]
    tabs = st.tabs(tab_titles)
    
    def display_df(df, tab):
        if not df.empty:
            tab.dataframe(df, hide_index=True, use_container_width=True)
        else:
            tab.info("No se encontraron eventos de este tipo.")

    display_df(pd.DataFrame(errores), tabs[0])
    display_df(pd.DataFrame(saltos_fvo), tabs[1])
    display_df(pd.DataFrame(ltrx_altos), tabs[2])
    display_df(pd.DataFrame(alarmas_preset), tabs[3])
    display_df(pd.DataFrame(ventas_no_cobradas), tabs[4])

    # Botón de exportación
    txt_export = exportar_txt(surtidor_num, ip, logs, errores, saltos_fvo, ltrx_altos, alarmas_preset, ventas_no_cobradas)
    st.download_button(
        label=f"📥 Descargar análisis de Surtidor {surtidor_num}",
        data=txt_export,
        file_name=f"analisis_surtidor_{surtidor_num}_{ip.replace(':', '_')}.txt",
        mime="text/plain"
    )

def exportar_txt(surtidor_num, ip, logs, errores, saltos_fvo, ltrx_altos, alarmas_preset, ventas_no_cobradas):
    """Genera un archivo de texto con tags para los eventos detectados."""
    tags = {}
    for e in errores: tags.setdefault(e["Línea"], []).append("[ERROR]")
    for s in saltos_fvo: tags.setdefault(s["Línea"], []).append("[SALTO_NUMERAL]")
    for l in ltrx_altos: tags.setdefault(l["Línea"], []).append("[LPM_ALTO]")
    for a in alarmas_preset: tags.setdefault(a["Línea"], []).append("[ALR_PRESET]")
    for n in ventas_no_cobradas: tags.setdefault(n["Línea"], []).append("[VENTA_NOCOBRADA]")
    
    output = StringIO()
    output.write(f"Análisis para Surtidor {surtidor_num} ({ip})\n")
    output.write("="*40 + "\n")
    for l in logs:
        tag_str = ''.join(tags.get(l["line"], []))
        extra = ''
        if 'EVT_PUMP_NEW_TRANSACTION' in l['text'] and l.get('id', 1) == 0 and '[SIN_ID]' not in l['text']:
            extra = ' [SIN_ID]'
        output.write(f"{l['line']:05d}: {l['text']}{extra} {tag_str}\n")
    return output.getvalue()

# --- Main App ---

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
        st.stop()

    # Definir claves y etiquetas de surtidores para la UI
    surtidor_keys = sorted(surtidores.keys(), key=lambda k: (k[1], k[0]))  # (ip, id)
    surtidor_labels = [f"Surtidor {k[1]} - IP {k[0]}" for k in surtidor_keys]

    # --- ALERTAS DE PROBLEMAS DE RED Y ENERGÍA ---
    # Alerta 1: Surtidores con más de una IP (problema de red)
    config_alerts = {}
    for idn, ips in id_to_ips.items():
        # Solo marcar como problema si hay más de una IP realmente distinta (no repeticiones)
        # Ignorar IPs Fusion fija en la alerta
        unique_ips = set(ip for ip in ips if not ip.startswith('195.180.178.'))
        if len(unique_ips) > 1:
            config_alerts[idn] = sorted(unique_ips)
    
    if config_alerts:
        with st.expander("⚠️ Problemas de Red Detectados", expanded=True):
            st.warning("Se detectaron surtidores respondiendo desde múltiples direcciones IP (excluyendo Fusion fija). Esto puede indicar un problema de red.")
            for idn, ips in config_alerts.items():
                st.markdown(f"- **Surtidor ID {idn}** se ha comunicado desde las siguientes IPs: `{', '.join(ips)}`")

    # Alerta 2: Posible corte de energía (60%+ surtidores en error en 2 minutos)
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
    else:
        # Debug info (puedes comentar esto después de verificar)
        if error_times:
            st.info(f"Debug: {len(error_times)} surtidores con error de {total_surtidores} total. Necesarios: 2+")

    with st.sidebar:
        st.subheader("Selección de Surtidor")
        selected_label = st.selectbox("Elige un surtidor", ["Mostrar todo"] + surtidor_labels)

    surtidor_map = dict(zip(surtidor_labels, surtidor_keys))
    selected_key = surtidor_map.get(selected_label) if surtidor_map and selected_label else None

    if selected_key:
        # Vista de un solo surtidor (por IP): mostrar todos los eventos de esa IP, sin importar el ID
        surtidor_ip, surtidor_num = selected_key
        # Unir todos los logs de esa IP (todos los IDs)
        all_logs = []
        for (ip, idn), logs_list in surtidores.items():
            if ip == surtidor_ip:
                all_logs.extend(logs_list)
        all_logs = sorted(all_logs, key=lambda l: l['line'])

        with st.sidebar:
            st.subheader("Filtrar Rango de Líneas")
            min_line = all_logs[0]['line']
            max_line = all_logs[-1]['line']
            line_range = st.slider("Selecciona un rango de líneas para analizar", min_line, max_line, (min_line, max_line))

        filtered_logs = [l for l in all_logs if line_range[0] <= l['line'] <= line_range[1]]
        # Marcar visualmente los NEW sin ID
        for l in filtered_logs:
            if l.get('id') == 0 and 'EVT_PUMP_NEW_TRANSACTION' in l['text'] and '[SIN_ID]' not in l['text']:
                l['text'] = l['text'] + ' [SIN_ID]'

        analysis_results = analyze_surtidor(surtidor_ip, surtidor_num, tuple(filtered_logs), ltrx_factor, salto_umbral, preset_over_factor, preset_under_factor)
        display_analysis_results(surtidor_num, surtidor_ip, filtered_logs, analysis_results)

        # Mostrar log completo del surtidor (filtrado)
        with st.expander("Ver Log Completo del Surtidor (filtrado)"):
            st.code('\n'.join([f"{l['line']:05d}: {l['text']}" for l in filtered_logs]), language="log")

    else:
        # Vista de "Mostrar todo"
        st.header("Análisis General de Todos los Surtidores")
        st.write(f"Se encontraron **{len(surtidor_keys)}** surtidores únicos (por IP) en el log.")

        for key in surtidor_keys:
            logs = surtidores[key]
            surtidor_ip, surtidor_num = key
            analysis_results = analyze_surtidor(surtidor_ip, surtidor_num, tuple(logs), ltrx_factor, salto_umbral, preset_over_factor, preset_under_factor)
            display_analysis_results(surtidor_num, surtidor_ip, logs, analysis_results)
            st.divider()

if __name__ == "__main__":
    main()