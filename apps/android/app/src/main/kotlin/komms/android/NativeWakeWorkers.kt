package komms.android

import android.content.Context
import androidx.work.Worker
import androidx.work.WorkerParameters

/** Bounded continuation for contact sets larger than one registration pass. */
class NativeWakeRegistrationWorker(
    context: Context,
    parameters: WorkerParameters,
) : Worker(context, parameters) {
    override fun doWork(): Result {
        if (NodeHolder.session == null || !NativeWakePlatform.supported(applicationContext)) {
            return Result.success()
        }
        return if (NativeWakeManager.continueRegistration(applicationContext)) {
            Result.retry()
        } else {
            Result.success()
        }
    }
}

/** One bounded continuation after Android deferred or shortened wake work. */
class NativeWakeCollectionWorker(
    context: Context,
    parameters: WorkerParameters,
) : Worker(context, parameters) {
    override fun doWork(): Result {
        NativeWakeManager.continueCollection()
        return Result.success()
    }
}
