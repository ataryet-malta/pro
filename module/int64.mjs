/* Copyright (C) 2023-2025 anonymous - PSFree Kernel Bridge Compatible */

const isInteger = Number.isInteger;

function check_not_in_range(x) {
    return !(isInteger(x) && -0x80000000 <= x && x <= 0xffffffff);
}

export function lohi_from_one(low) {
    if (low instanceof Int) {
        return [low.lo, low.hi];
    }
    if (check_not_in_range(low)) {
        throw TypeError(`low not a 32-bit integer: ${low}`);
    }
    return [low >>> 0, low < 0 ? -1 >>> 0 : 0];
}

export class Int {
    constructor(low, high) {
        if (high === undefined) {
            const res = lohi_from_one(low);
            this._u32 = new Uint32Array(res);
            return;
        }
        if (check_not_in_range(low) || check_not_in_range(high)) {
            throw TypeError("Invalid 64-bit component range");
        }
        this._u32 = new Uint32Array([low, high]);
    }

    get lo() { return this._u32[0]; }
    get hi() { return this._u32[1]; }

    add(b) {
        const values = lohi_from_one(b);
        const low = this.lo + values[0];
        // الحساب الدقيق للـ Carry لضمان الوصول لعناوين الـ Kernel العالية
        const carry = (low > 0xffffffff) ? 1 : 0;
        return new Int((low >>> 0), (this.hi + values[1] + carry) >>> 0);
    }

    sub(b) {
        const values = lohi_from_one(b);
        const low = this.lo - values[0];
        const borrow = (this.lo < values[0]) ? 1 : 0;
        return new Int((low >>> 0), (this.hi - values[1] - borrow) >>> 0);
    }

    toString() {
        return '0x' + this.hi.toString(16).padStart(8, '0') + this.lo.toString(16).padStart(8, '0');
    }
}

// التصدير المزدوج لضمان عدم ظهور "Import Error"
export { Int as Int64 };
export default Int;
