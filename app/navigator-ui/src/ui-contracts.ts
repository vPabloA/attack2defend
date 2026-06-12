import { runGraphRenderPlanContractFixture } from './graph/graphRenderPlan.contract.test.ts';
import { runReviewQueueLayoutContractFixture } from './lib/reviewQueueLayout.contract.test.ts';
import { runTier1ReadoutLayoutContractFixture } from './lib/tier1ReadoutLayout.contract.test.ts';

runGraphRenderPlanContractFixture();
runReviewQueueLayoutContractFixture();
runTier1ReadoutLayoutContractFixture();

console.log('ui-contracts: ok');
