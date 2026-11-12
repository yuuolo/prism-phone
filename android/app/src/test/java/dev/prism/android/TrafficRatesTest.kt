package dev.prism.android

import org.junit.Assert.*
import org.junit.Test

class TrafficRatesTest {
    @Test fun usesActualElapsedTimeAndIncludesIdleSamples() {
        val rates=TrafficRates()
        assertNull(rates.sample(TrafficRates.Sample("a",100,100,200)))
        assertEquals(TrafficRates.Rates(200,400),rates.sample(TrafficRates.Sample("a",1600,400,800)))
        assertEquals(TrafficRates.Rates(0,0),rates.sample(TrafficRates.Sample("a",2600,400,800)))
    }

    @Test fun reconnectAndCounterResetNeverProduceSpikes() {
        val rates=TrafficRates()
        rates.sample(TrafficRates.Sample("a",1000,10000,20000))
        assertNull(rates.sample(TrafficRates.Sample("b",2000,50000,60000)))
        assertNull(rates.sample(TrafficRates.Sample("b",3000,10,20)))
        assertEquals(TrafficRates.Rates(10,20),rates.sample(TrafficRates.Sample("b",4000,20,40)))
    }

    @Test fun pauseAndLongGapsRequireNewBaseline() {
        val rates=TrafficRates()
        rates.sample(TrafficRates.Sample("a",1000,0,0))
        assertNull(rates.sample(TrafficRates.Sample("a",10000,9000,9000)))
        assertNull(rates.sample(TrafficRates.Sample("a",10000,9000,9000)))
        rates.reset()
        assertNull(rates.sample(TrafficRates.Sample("a",11000,10000,10000)))
        assertEquals(TrafficRates.Rates(1000,1000),rates.sample(TrafficRates.Sample("a",12000,11000,11000)))
    }
}
